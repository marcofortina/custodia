{{/*
Copyright (c) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-only

This file is part of Custodia.
Custodia is distributed under the GNU Affero General Public License v3.0.
See the accompanying LICENSE file for details.
*/}}

{{- define "custodia.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "custodia.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "custodia.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}


{{- define "custodia.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "custodia.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}


{{- define "custodia.serverFullname" -}}
{{- printf "%s-server" (include "custodia.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "custodia.signerFullname" -}}
{{- printf "%s-signer" (include "custodia.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "custodia.persistenceClaimName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "custodia.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
