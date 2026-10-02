# byoi-signing-demo
Test image for wso2-enterprise/choreo#40100 (build provenance for BYOI).
`build-sign.yml` builds and pushes on every branch, and signs + attests provenance **only on `main`** with cosign.
`tamper.yml` (manual) overwrites the `:main` tag with an unsigned image to demonstrate mutable-tag risk.
