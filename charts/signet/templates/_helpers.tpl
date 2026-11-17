{{- define "signet.name" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "signet.labels" -}}
app.kubernetes.io/name: signet
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}
