# Multi-arch build: Go cross-compiles for the target platform, no emulation needed.
FROM --platform=$BUILDPLATFORM golang:1.25.14-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/signature-webhook .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/signature-webhook /signature-webhook
USER 65532:65532
ENTRYPOINT ["/signature-webhook"]
