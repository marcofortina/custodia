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
