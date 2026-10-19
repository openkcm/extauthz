# OpenKCM ExtAuthZ Helm chart

This chart deploys [OpenKCM ExtAuthZ](https://openkcm.io/components/cmk/extauthz),
the external authorization service for Envoy Gateway. Envoy Gateway sends every
protected request to ExtAuthZ; ExtAuthZ authenticates the caller (client
certificate, bearer token or browser session), evaluates Cedar policies, and adds
signed client data for the backend.

Every value is documented in [values.yaml](values.yaml). Every setting of ExtAuthZ
itself, under `config`, is described in the
[ExtAuthZ configuration reference](https://openkcm.io/components/cmk/security/extauthz-config).
The [configuration guide](https://openkcm.io/components/cmk/security/configuration)
shows the complete setup with Envoy Gateway, Session Manager and CMK.

## What the chart creates

| Resource | Purpose |
| --- | --- |
| Deployment | The ExtAuthZ pods |
| ConfigMap | The configuration, rendered from `config` and mounted at `/etc/extauthz` |
| Service | ext_authz gRPC API (9092) and status endpoints (8080) inside the cluster |
| ServiceAccount | Identity of the pods. ExtAuthZ does not call the Kubernetes API, so no token is mounted |
| NetworkPolicy | Optional (`networkPolicy.enabled`): who may reach the pods |
| PodDisruptionBudget | Optional (`pod.disruptionBudget.enabled`) |
| HorizontalPodAutoscaler | Optional (`hpa.enabled`) |

## Objects you create

With the default values, the pods mount these objects from the release
namespace. The chart does not create them, and the pods do not start until they
exist:

| Object | Mounted at | Content |
| --- | --- | --- |
| ConfigMap `extauthz-trusted-subjects` | `/etc/extauthz-mtls` | `trustedSubjects.yaml`: client certificate subjects and their regions |
| ConfigMaps `extauthz-systems-policies`, `extauthz-users-policies` | `/etc/extauthz-policies` | Cedar policy files (`*.cedar`) |
| Secret `extauthz-signing-keys-secret` | `/etc/extauthz-signing` | `keyId` and the RSA private key `<keyId>.pem` for signing client data |
| Secret with the CSRF secret, if you enable `config.sessionManager` | Your choice, through `extraVolumes` | The same secret as Session Manager's |

Examples are in the repository's [examples](../../examples) directory. To use
other names or paths, override `extraVolumes`, `extraVolumeMounts` and the
matching paths under `config`.

## Prerequisites

- Kubernetes 1.23 or later (`autoscaling/v2`), and Helm 3 or later.
- Envoy Gateway, configured to call ExtAuthZ with a `SecurityPolicy`
  (`extAuth.grpc`) and to forward client certificates (`x-forwarded-client-cert`).
- For browser sessions: Session Manager, and the CSRF secret shared with it.

## Install

```yaml
# extauthz-values.yaml
# image.tag defaults to the chart's appVersion; set it only to deploy another version.

replicaCount: 2

networkPolicy:
  enabled: true
  grpc:
    from:
      - podSelector: { matchLabels: { app.kubernetes.io/name: envoy } }

extraVolumes:
  - name: extauthz-trusted-subjects-volume
    configMap: { name: extauthz-trusted-subjects }
  - name: extauthz-policies-volume
    projected:
      sources:
        - configMap: { name: extauthz-systems-policies }
        - configMap: { name: extauthz-users-policies }
  - name: extauthz-signing-keys-volume
    projected:
      sources:
        - secret: { name: extauthz-signing-keys-secret }
  - name: csrf-secret
    secret:
      secretName: csrf-secret
      items: [{ key: csrf_secret, path: csrf_secret }]
extraVolumeMounts:
  - { name: extauthz-trusted-subjects-volume, mountPath: /etc/extauthz-mtls, readOnly: true }
  - { name: extauthz-policies-volume, mountPath: /etc/extauthz-policies, readOnly: true }
  - { name: extauthz-signing-keys-volume, mountPath: /etc/extauthz-signing, readOnly: true }
  - { name: csrf-secret, mountPath: /etc/credentials/csrf-secret, readOnly: true }

config:
  jwt:
    providers:
      - issuer: https://idp.example.com/realms/platform
        audiences: [cmk-api]
  sessionManager:
    enabled: true
    address: session-manager.services.svc.cluster.local:9091
    secretRef: { type: insecure }    # inside a service mesh with mutual TLS
  csrfSecret:
    source: file
    file: { path: /etc/credentials/csrf-secret/csrf_secret, format: binary }
```

```sh
helm upgrade --install extauthz ./charts/extauthz -n envoy-gateway-system -f extauthz-values.yaml
```

The release notes list the objects the pods need and warn about settings that
are not production-ready.

## Important values

| Value | Default | Description |
| --- | --- | --- |
| `image.tag` / `image.digest` | chart's `appVersion` | The ExtAuthZ version to deploy. Leave both empty to deploy the version this chart release is made for |
| `image.repository` | `extauthz/images/extauthz` | Under `ghcr.io/openkcm` |
| `replicaCount` | `1` | Use two or more in production; every API request passes ExtAuthZ |
| `networkPolicy.enabled` | `false` | **Recommended.** Allow only Envoy Gateway to call the gRPC API |
| `extraVolumes`, `extraVolumeMounts` | policies, trusted subjects, signing keys | Replace both lists when you add your own volumes |
| `config.jwt.providers` | `[]` | Statically trusted token issuers for technical users |
| `config.sessionManager` | disabled | Browser sessions through Session Manager |
| `config.csrfSecret` | not set | Required with `sessionManager`; the same bytes as Session Manager's secret |
| `config.audit`, `config.valkey` | not set | Audit events and burst detection |
| `resources` | 100m CPU, 128Mi memory and 128Mi ephemeral storage requested; 512Mi memory and 512Mi ephemeral storage limits | |
| `hpa.enabled` | `false` | Autoscale on CPU and memory |

## Security defaults

| Setting | Default |
| --- | --- |
| Pod | Non-root (user and group 65532), `RuntimeDefault` seccomp profile, no ServiceAccount token, no Service environment variables |
| Container | No privilege escalation, all capabilities dropped, read-only root filesystem, writable `/tmp` |
| gRPC reflection | Off |
| Profiling endpoints | Off |
| Log level | `info` |

ExtAuthZ trusts the client certificate information that its caller passes in
the request. Only Envoy Gateway, which sets that information from the TLS
connection, may call the gRPC API: keep the Service type `ClusterIP`, enable
`networkPolicy`, and run ExtAuthZ in a service mesh with mutual TLS.

## Network policy

With `networkPolicy.enabled: true`, the chart allows ingress only from the peers
in `networkPolicy.grpc.from` (ext_authz gRPC API) and `networkPolicy.status.from`
(status port, for example a metrics collector). An empty list denies all
callers of that port. Outgoing traffic is not restricted. Probes from the
kubelet are not affected on most network plugins.

## Configuration changes

ExtAuthZ reads its configuration, policies, trusted subjects and CSRF secret at
startup. The chart adds a `checksum/config` annotation to the pods, so a change
under `config` restarts them during `helm upgrade`. Changes to the ConfigMaps and
Secrets you manage yourself need a restart:
`kubectl rollout restart deployment/<release>-extauthz`.

[templates/configmap.yaml](templates/configmap.yaml) writes `config.yaml` with one
section per setting: `config.environment` and `config.labels` become
`application.environment` and `application.labels`; `featureGates`, `logger`, `status`,
`telemetry`, `grpcServer`, `cedar`, `mtls`, `jwt`, `clientData`, `audit`, `valkey`,
`sessionPathPrefixes`, `sessionManager` and `csrfSecret` are written as they are. Other
keys under `config` are not written, so check a key's spelling when it has no effect.

## Upgrading from 0.14.x

| Change | Action |
| --- | --- |
| Default image repository is now `extauthz/images/extauthz` (was `images/checker`) | If you set `image.repository` yourself, nothing changes |
| No `imagePullSecrets` by default (was `registry-access`) | Set `imagePullSecrets` if you pull from a private registry |
| `replicas` comes from `replicaCount` and is omitted when `hpa.enabled` is true (was `hpa.minReplicas`, only with the autoscaler) | Set `replicaCount`; with the autoscaler, upgrades no longer reset the replica count |
| The ConfigMap is named after the release (`<release>-extauthz-config`) | None; for a release named `extauthz` the name stays `extauthz-config` |
| `config.sessionManager` is disabled by default (was enabled with `localhost:5555`) | Configure it explicitly, with `csrfSecret` |
| `config.jwt.providers` is empty by default (was a placeholder issuer) | Configure your issuers |
| New security defaults, probes and resource requests | Override `securityContext`, `pod.securityContext`, the probes and `resources` if needed |
| `config.logger.level` defaults to `info`, `config.environment` to `production` | Set them explicitly if you rely on the old values |
| `serviceAccount.automount` defaults to `false` | The pod never mounted the token; only the ServiceAccount object changes |
| PodDisruptionBudget without `minAvailable` or `maxUnavailable` uses `maxUnavailable: 1` | Set `minAvailable` explicitly if you want the old behaviour |
| `config.isImmutable` is replaced by `configMap.immutable` | The old key still works |

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Pods stay in `ContainerCreating` | A ConfigMap or Secret from [Objects you create](#objects-you-create) is missing |
| Pod exits with `has invalid keys` | A key under `config` is not an ExtAuthZ setting |
| Pod exits with an error about trusted subjects | `trustedSubjects.yaml` is missing or invalid |
| Every authenticated request gets `403` | No Cedar policy was loaded: check that the policy files end in `.cedar` and are directly in `config.cedar.policyPath` |
| Browser requests fail with `CSRF token is not valid` | `config.csrfSecret` differs from Session Manager's secret, or is not set |

## Uninstall

```sh
helm uninstall extauthz -n envoy-gateway-system
```

The ConfigMaps and Secrets you created yourself are not removed.
