FROM golang:1.22-alpine AS builder
ARG GO_BUILD_TAGS=""
ARG CUSTODIA_VERSION="dev"
ARG CUSTODIA_COMMIT="unknown"
ARG CUSTODIA_DATE="unknown"
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w -X custodia/internal/build.Version=${CUSTODIA_VERSION} -X custodia/internal/build.Commit=${CUSTODIA_COMMIT} -X custodia/internal/build.Date=${CUSTODIA_DATE}" -o /out/custodia-server ./cmd/custodia-server \
 && go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w -X custodia/internal/build.Version=${CUSTODIA_VERSION} -X custodia/internal/build.Commit=${CUSTODIA_COMMIT} -X custodia/internal/build.Date=${CUSTODIA_DATE}" -o /out/vault-admin ./cmd/vault-admin

FROM alpine:3.21
RUN addgroup -S custodia && adduser -S -G custodia custodia
USER custodia
WORKDIR /app
COPY --from=builder /out/custodia-server /usr/local/bin/custodia-server
COPY --from=builder /out/vault-admin /usr/local/bin/vault-admin
EXPOSE 8443 8080
ENTRYPOINT ["/usr/local/bin/custodia-server"]
