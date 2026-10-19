{{/*
Expand the name of the chart.
*/}}
{{- define "extauthz.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "extauthz.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Namespace for all resources. Defaults to the release namespace.
See https://github.com/helm/helm/issues/5358
*/}}
{{- define "extauthz.namespace" -}}
{{- .Values.namespace | default .Release.Namespace }}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "extauthz.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Version of the deployed application: the image tag if set, else the chart's appVersion.
*/}}
{{- define "extauthz.version" -}}
{{- (.Values.image.tag | default .Chart.AppVersion) | toString | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "extauthz.labels" -}}
helm.sh/chart: {{ include "extauthz.chart" . }}
{{ include "extauthz.selectorLabels" . }}
{{- with include "extauthz.version" . }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels. Do not change them: a Deployment's selector cannot be changed on upgrade.
*/}}
{{- define "extauthz.selectorLabels" -}}
app.kubernetes.io/name: {{ include "extauthz.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .Chart.Name }}
{{- end }}

{{/*
Name of the service account to use.
*/}}
{{- define "extauthz.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "extauthz.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference: registry and repository, then the digest if set, else the tag. The tag
defaults to the chart's appVersion, the image version this chart release is made for.
Call it with (tuple .Values.image .Chart.AppVersion).
*/}}
{{- define "extauthz.image" -}}
{{- $image := index . 0 -}}
{{- $appVersion := index . 1 -}}
{{- $repository := $image.repository -}}
{{- if $image.registry -}}{{- $repository = printf "%s/%s" $image.registry $image.repository -}}{{- end -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $repository (toString $image.digest) -}}
{{- else -}}
{{- printf "%s:%s" $repository (toString ($image.tag | default $appVersion)) -}}
{{- end -}}
{{- end }}

{{/*
Whether the configuration ConfigMap is immutable. configMap.immutable is preferred;
config.isImmutable is still honoured for compatibility with older values files.
*/}}
{{- define "extauthz.configImmutable" -}}
{{- if or .Values.configMap.immutable .Values.config.isImmutable -}}
true
{{- end -}}
{{- end }}

{{/*
Name of the configuration ConfigMap. An immutable ConfigMap gets a hash in its name, so that
a changed configuration creates a new ConfigMap instead of failing the upgrade. config.yaml
(templates/configmap.yaml) is made of the values under config, the chart name and the chart
version, so the hash covers these.
*/}}
{{- define "extauthz.configMapName" -}}
{{- if include "extauthz.configImmutable" . -}}
{{- $hash := printf "%s\n%s\n%s" .Chart.Version (include "extauthz.name" .) (toYaml .Values.config) | sha256sum | trunc 10 }}
{{- printf "%s-config-%s" (include "extauthz.fullname" . | trunc 45 | trimSuffix "-") $hash }}
{{- else -}}
{{- printf "%s-config" (include "extauthz.fullname" . | trunc 56 | trimSuffix "-") }}
{{- end -}}
{{- end }}
