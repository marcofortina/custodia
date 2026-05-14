# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# Lab-only SoftHSM image overlay for Kubernetes Full PKCS#11 smoke.
# Do not use this image as production HSM evidence.

ARG CUSTODIA_IMAGE
FROM ${CUSTODIA_IMAGE}

USER root
RUN apk add --no-cache bash opensc python3 softhsm
COPY scripts/pkcs11-sign-command.sh /usr/local/bin/custodia-pkcs11-sign
RUN chmod 0755 /usr/local/bin/custodia-pkcs11-sign \
 && mkdir -p /var/lib/softhsm/tokens /run/custodia-softhsm \
 && chown -R 65532:65532 /var/lib/softhsm /run/custodia-softhsm
USER 65532:65532
