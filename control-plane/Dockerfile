# control-plane: статический бинарник на distroless, не root. Собирает и подписывает release.yaml (cosign keyless).
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /control-plane ./cmd/control-plane
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /control-plane /control-plane
USER 65532:65532
ENTRYPOINT ["/control-plane"]
