{{- define "signet.name" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "signet.labels" -}}
app.kubernetes.io/name: signet
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
