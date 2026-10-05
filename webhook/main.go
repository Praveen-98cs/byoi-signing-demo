// signature-webhook: a Kubernetes ValidatingAdmissionWebhook that lets a workload into a critical
// environment only if every image is signed by the trusted key AND its signed provenance says the
// image was built from the allowed branch (default: main).
//
// Which namespaces are "critical" is decided by the ValidatingWebhookConfiguration's namespaceSelector,
// not by this code: the API server only calls us for matching requests.
//
// Per image:  resolve tag -> digest, verify cosign signature, verify in-toto provenance, branch == main?
// Results are cached by DIGEST (never by tag), so a re-pushed tag is always checked again.
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const provenanceType = "https://choreo.dev/provenance/v1"

type verdict struct {
	ok      bool
	reason  string
	expires time.Time
}

type webhook struct {
	verifier        signature.Verifier
	allowedBranch   string
	trustedPrefixes []string
	sigRepo         string // optional: where signatures live, like COSIGN_REPOSITORY
	cacheTTL        time.Duration
	budget          time.Duration

	mu    sync.Mutex
	cache map[string]verdict // key: repo@sha256 digest
}

func main() {
	addr := flag.String("addr", ":8443", "listen address (HTTPS)")
	certFile := flag.String("tls-cert", "/tls/tls.crt", "TLS certificate")
	keyFile := flag.String("tls-key", "/tls/tls.key", "TLS key")
	pubKey := flag.String("key", "/keys/cosign.pub", "trusted cosign public key (PEM)")
	allowed := flag.String("allowed-branch", "main", "branch allowed into critical environments")
	trusted := flag.String("trusted-prefixes", "", "comma-separated image prefixes that are always allowed (platform images)")
	sigRepo := flag.String("signature-repo", "", "optional repository that holds signatures (like COSIGN_REPOSITORY)")
	ttl := flag.Duration("cache-ttl", 10*time.Minute, "how long a per-digest result is cached")
	budget := flag.Duration("verify-timeout", 15*time.Second, "time budget per admission request; keep it BELOW the webhook's timeoutSeconds so we answer before the API server gives up")
	flag.Parse()

	pemBytes, err := os.ReadFile(*pubKey)
	must(err, "read public key")
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	must(err, "parse public key")
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	must(err, "load verifier")

	wh := &webhook{verifier: verifier, allowedBranch: *allowed, sigRepo: *sigRepo, cacheTTL: *ttl, budget: *budget, cache: map[string]verdict{}}
	for _, p := range strings.Split(*trusted, ",") {
		if p = strings.TrimSpace(p); p != "" {
			wh.trustedPrefixes = append(wh.trustedPrefixes, p)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", wh.serveValidate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second}
	log.Printf("signature-webhook listening on %s (allowed branch=%s, trusted prefixes=%v, signature repo=%q)",
		*addr, *allowed, wh.trustedPrefixes, *sigRepo)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

func (wh *webhook) serveValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil || review.Request == nil {
		http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
		return
	}
	req := review.Request
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}

	images, err := imagesOf(req.Kind.Kind, req.Object.Raw)
	if err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Code: http.StatusBadRequest, Message: "signature-webhook: cannot read workload: " + err.Error()}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), wh.budget)
		defer cancel()
		var problems []string
		for _, img := range images {
			if wh.trusted(img) {
				log.Printf("   %s %s/%s: %s -> trusted platform image", req.Operation, req.Namespace, req.Name, img)
				continue
			}
			if ok, reason := wh.check(ctx, img); !ok {
				problems = append(problems, fmt.Sprintf("%s -> %s", img, reason))
			}
		}
		if len(problems) > 0 {
			resp.Allowed = false
			resp.Result = &metav1.Status{Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
				Message: fmt.Sprintf("signature-webhook: only images built from %s may run in this critical environment: %s",
					wh.allowedBranch, strings.Join(problems, "; "))}
		}
	}
	log.Printf("%s %s %s/%s allowed=%v", req.Operation, req.Kind.Kind, req.Namespace, req.Name, resp.Allowed)

	review.Response = resp
	review.Request = nil
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

func (wh *webhook) trusted(img string) bool {
	for _, p := range wh.trustedPrefixes {
		if strings.HasPrefix(img, p) {
			return true
		}
	}
	return false
}

// check verifies one image and returns (allowed, reason). Cached per digest.
func (wh *webhook) check(ctx context.Context, img string) (bool, string) {
	ref, err := name.ParseReference(img)
	if err != nil {
		log.Printf("   %s ok=false invalid image reference", img)
		return false, "invalid image reference"
	}
	desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		log.Printf("   %s ok=false cannot resolve digest: %s", img, oneLine(err))
		return false, "cannot resolve digest: " + oneLine(err)
	}
	pinned := ref.Context().Digest(desc.Digest.String())
	key := pinned.String()

	wh.mu.Lock()
	if v, ok := wh.cache[key]; ok && time.Now().Before(v.expires) {
		wh.mu.Unlock()
		log.Printf("   %s (cached) ok=%v %s", key, v.ok, v.reason)
		return v.ok, v.reason
	}
	wh.mu.Unlock()

	ok, reason := wh.verify(ctx, pinned)
	log.Printf("   %s ok=%v %s", key, ok, reason)
	wh.mu.Lock()
	wh.cache[key] = verdict{ok: ok, reason: reason, expires: time.Now().Add(wh.cacheTTL)}
	wh.mu.Unlock()
	return ok, reason
}

func (wh *webhook) verify(ctx context.Context, pinned name.Digest) (bool, string) {
	regOpts := []ociremote.Option{ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))}
	if wh.sigRepo != "" {
		repo, err := name.NewRepository(wh.sigRepo)
		if err != nil {
			return false, "bad signature repository"
		}
		regOpts = append(regOpts, ociremote.WithTargetRepository(repo))
	}
	co := &cosign.CheckOpts{SigVerifier: wh.verifier, IgnoreTlog: true, IgnoreSCT: true,
		ClaimVerifier: cosign.SimpleClaimVerifier, RegistryClientOpts: regOpts}
	if _, _, err := cosign.VerifyImageSignatures(ctx, pinned, co); err != nil {
		return false, "not signed by the trusted key (" + oneLine(err) + ")"
	}
	co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	atts, _, err := cosign.VerifyImageAttestations(ctx, pinned, co)
	if err != nil {
		return false, "no valid signed provenance (" + oneLine(err) + ")"
	}
	for _, att := range atts {
		if branch, commit, ok := readProvenance(att); ok {
			if branch == wh.allowedBranch {
				return true, fmt.Sprintf("signed, built from %s (commit %s)", branch, short(commit))
			}
			return false, fmt.Sprintf("built from branch '%s' (commit %s)", branch, short(commit))
		}
	}
	return false, "signed, but no provenance of type " + provenanceType
}

func readProvenance(att interface{ Payload() ([]byte, error) }) (string, string, bool) {
	raw, err := att.Payload()
	if err != nil {
		return "", "", false
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", "", false
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Branch string `json:"branch"`
			Commit string `json:"commit"`
		} `json:"predicate"`
	}
	if json.Unmarshal(b, &stmt) != nil || stmt.PredicateType != provenanceType {
		return "", "", false
	}
	return stmt.Predicate.Branch, stmt.Predicate.Commit, true
}

// imagesOf returns every container and init-container image of a supported workload kind.
func imagesOf(kind string, raw []byte) ([]string, error) {
	var spec corev1.PodSpec
	switch kind {
	case "Deployment":
		var o appsv1.Deployment
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.Template.Spec
	case "StatefulSet":
		var o appsv1.StatefulSet
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.Template.Spec
	case "DaemonSet":
		var o appsv1.DaemonSet
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.Template.Spec
	case "Job":
		var o batchv1.Job
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.Template.Spec
	case "CronJob":
		var o batchv1.CronJob
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.JobTemplate.Spec.Template.Spec
	case "Pod":
		var o corev1.Pod
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec
	default:
		return nil, nil
	}
	var imgs []string
	for _, c := range spec.InitContainers {
		imgs = append(imgs, c.Image)
	}
	for _, c := range spec.Containers {
		imgs = append(imgs, c.Image)
	}
	return imgs, nil
}

func oneLine(err error) string { return strings.ReplaceAll(err.Error(), "\n", " ") }

func short(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
