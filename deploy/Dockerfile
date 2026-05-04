# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

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
 && go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w -X custodia/internal/build.Version=${CUSTODIA_VERSION} -X custodia/internal/build.Commit=${CUSTODIA_COMMIT} -X custodia/internal/build.Date=${CUSTODIA_DATE}" -o /out/custodia-admin ./cmd/custodia-admin \
 && go build -tags="${GO_BUILD_TAGS}" -trimpath -ldflags="-s -w -X custodia/internal/build.Version=${CUSTODIA_VERSION} -X custodia/internal/build.Commit=${CUSTODIA_COMMIT} -X custodia/internal/build.Date=${CUSTODIA_DATE}" -o /out/custodia-signer ./cmd/custodia-signer

FROM alpine:3.23
RUN addgroup -S custodia && adduser -S -G custodia custodia
WORKDIR /app
COPY --from=builder /out/custodia-server /usr/local/bin/custodia-server
COPY --from=builder /out/custodia-admin /usr/local/bin/custodia-admin
COPY --from=builder /out/custodia-signer /usr/local/bin/custodia-signer
USER custodia
EXPOSE 8443 8080 9444
ENTRYPOINT ["/usr/local/bin/custodia-server"]
