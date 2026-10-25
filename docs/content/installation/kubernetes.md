---
title: Kubernetes
description: Run the DeaconGuard server in Kubernetes, and an agent on every node, with Helm or Kustomize.
---

In Kubernetes, DeaconGuard runs as two parts, usually in two namespaces:

- **The server**, a StatefulSet with one pod and a volume for its database, behind a Service with the dashboard on port 8443 and the agent API on 8444. It runs under the **restricted** [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/): non-root, read-only root filesystem, no capabilities.
- **The agent**, a DaemonSet with one pod on every node, control plane included. Each pod scans **its node**: it reads the node's root filesystem, read-only, and runs the same fixed, read-only checks there with the node's own tools, so its results match an agent [installed on the node](./install-script.md). It needs the **privileged** Pod Security Standard for that: the node's processes, network and filesystem. With the [Running containers](../usage/containers.md) check, a node's scan also covers the containers of its pods.

Agents enroll with a [reusable token](../usage/agents.md#reusable-tokens): one token, in a secret, for every node, including nodes added later.

You can run just the agent DaemonSet, with the server elsewhere, or just the server, with agents on machines outside the cluster.

## With Helm

The chart is published as an OCI artifact, [signed](../security/verify-a-release.md#the-container-image-and-the-helm-chart) like the image:

```text
oci://ghcr.io/cloudopsshell/charts/deaconguard
```

### 1. The server

```bash
kubectl create namespace deaconguard --save-config
kubectl label namespace deaconguard pod-security.kubernetes.io/enforce=restricted
kubectl -n deaconguard create secret generic deaconguard-admin --from-literal=password="$(openssl rand -base64 18)"
helm install deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" \
  -n deaconguard --set server.admin.existingSecret=deaconguard-admin
```

The server creates the account `admin` with that password on its first start, and ignores the secret once any account exists. Read the password with `kubectl -n deaconguard get secret deaconguard-admin -o jsonpath='{.data.password}' | base64 -d`, and change it under **My account** after signing in.

If you install the chart before creating the secret, the server waits for it rather than failing: its page and its log say which secret to create, and it starts within a minute or so of the secret appearing. If it hasn't after two minutes, delete the pod (`kubectl -n deaconguard delete pod deaconguard-0`) so it mounts the secret.

Open the dashboard:

```bash
kubectl -n deaconguard port-forward svc/deaconguard 8443:8443
```

and go to `https://127.0.0.1:8443`. The certificate is self-signed until you [give it one](#certificates-and-ingress).

### 2. A reusable token

On the **Agents** page, choose **Enroll a machine**, then **Many machines**. As the server address, use the Service's agent port, which the dialog fills in when you opened the dashboard through `port-forward`:

```text
https://deaconguard.deaconguard.svc:8444
```

Not `https://127.0.0.1:8444`: through a port-forward, `127.0.0.1` is your own computer, and in an agent's pod or on another machine it is that pod or machine, so the agent would never reach the server. The dialog warns about loopback addresses.

Give the token a name, such as the cluster's, pick how long it lasts, and create it. Or, from the command line:

```bash
kubectl -n deaconguard exec deaconguard-0 -- deaconguard token create \
  --server-url https://deaconguard.deaconguard.svc:8444 --reusable --days 90 --name production --quiet
```

### 3. The agents

```bash
kubectl create namespace deaconguard-agent --save-config
kubectl label namespace deaconguard-agent pod-security.kubernetes.io/enforce=privileged
kubectl -n deaconguard-agent create secret generic deaconguard-enrollment --from-literal=token='deaconguard1.…'
helm install deaconguard-agent oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" \
  -n deaconguard-agent --set server.enabled=false --set agent.enabled=true \
  --set agent.enrollment.existingSecret=deaconguard-enrollment
```

Each node appears on the **Agents** page within a minute, named after the node, and the token's row counts them. Scan or [audit](../usage/audits.md) them like any other host.

### 4. The cluster itself

The agents check the nodes. To check the cluster too (its workloads, RBAC, namespaces, Kubernetes version and API server; see [Kubernetes clusters](../usage/kubernetes.md)), turn on the cluster agent. It runs as one unprivileged pod with a read-only ClusterRole (get, list and watch) that can't read secrets, and enrolls with a token like the agents (DeaconGuard 1.5.0 and later):

```bash
kubectl -n deaconguard-agent create secret generic deaconguard-cluster-enrollment --from-literal=token='deaconguard1.…'
helm upgrade deaconguard-agent oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" -n deaconguard-agent --reset-then-reuse-values \
  --set cluster.enabled=true --set cluster.name=production \
  --set cluster.enrollment.existingSecret=deaconguard-cluster-enrollment
```

The cluster appears on **Hosts** as `production`, a Kubernetes cluster, and runs the Kubernetes check only: from **Scan now**, or on a [schedule](../usage/dashboard.md#schedules) with the Kubernetes check ticked. It keeps its identity on a small volume (16 MiB), so the cluster needs a default storage class, or `cluster.persistence.storageClass`.

### Values

| Value | Default | Use |
| --- | --- | --- |
| `image.repository`, `image.tag` | `ghcr.io/cloudopsshell/deaconguard`, the chart's version | Another registry, such as a mirror |
| `imagePullSecrets` | `[]` | For a private mirror |
| `server.enabled` | `true` | Install the server |
| `server.admin.username` | `admin` | The first account |
| `server.admin.existingSecret`, `server.admin.secretKey` | `""`, `password` | The secret with its password |
| `server.admin.password` | `""` | Or the password itself, which the chart puts in a secret (it is then also in Helm's release data) |
| `server.trustedProxies` | `[]` | Networks of the proxies in front of the dashboard, such as the ingress controller's pods; see [Behind a reverse proxy](../security/securing-the-dashboard.md#behind-a-reverse-proxy) |
| `server.tls.existingSecret` | `""` | A `kubernetes.io/tls` secret to serve instead of the self-signed certificate |
| `server.persistence.size`, `.storageClass`, `.existingClaim` | `5Gi`, the default class, none | The database's volume |
| `server.service.type`, `.annotations`, `.dashboardPort`, `.agentPort` | `ClusterIP`, none, `8443`, `8444` | The Service |
| `server.agentService.enabled`, `.type`, `.annotations`, `.loadBalancerSourceRanges`, `.port` | off, `LoadBalancer`, none, none, `8444` | A Service with only the agent port, for [agents outside the cluster](#agents-outside-the-cluster) |
| `server.agentService.externalTrafficPolicy`, `.loadBalancerClass`, `.nodePort` | the cluster's defaults | `Local` keeps each agent's own address in the server's logs; the load balancer implementation to use, when there are several; a fixed node port (30000–32767) instead of a random one |
| `server.ingress.enabled`, `.className`, `.annotations`, `.hosts`, `.tls` | off | An Ingress for the dashboard |
| `server.ingress.traefik.enabled`, `.allowSourceRanges`, `.middlewares` | off, none, none | With Traefik (chart 1.11.0 and later): the ServersTransport and Service annotations Traefik needs to reach the dashboard, an IP allow list, and other middlewares; see [With Traefik](#with-traefik) |
| `server.agentRoute.enabled`, `.host`, `.entryPoints` | off, none, `[websecure]` | Agents outside the cluster through Traefik on port 443, with TLS passed through (chart 1.11.0 and later); see [With Traefik](#with-traefik) |
| `server.resources` | 100m CPU, 256 MiB requested; 1 GiB limit | The server needs about 450 MB while it checks an Ubuntu machine's packages |
| `agent.enabled` | `false` | Install the agent DaemonSet |
| `agent.enrollment.existingSecret`, `.secretKey` | `""`, `token` | The secret with the reusable token |
| `agent.enrollment.token` | `""` | Or the token itself, which the chart puts in a secret |
| `agent.identityPath` | `/var/lib/deaconguard-agent` | Where each node keeps its agent's identity |
| `agent.resources` | 50m CPU, 128 MiB requested; 2.5 GiB limit | ClamAV, when the node has it, runs inside this limit and needs about 1.5 GB |
| `agent.tolerations` | every taint | Which nodes get an agent; with `agent.nodeSelector` and `agent.affinity` |
| `agent.priorityClassName` | `""` | |
| `cluster.enabled` | `false` | Install the cluster agent, which checks the cluster through its API |
| `cluster.name` | `kubernetes` | The cluster's name on the server |
| `cluster.enrollment.existingSecret`, `.secretKey`, `.token` | `""`, `token`, `""` | Its enrollment token, as for the agents |
| `cluster.persistence.size`, `.storageClass` | `16Mi`, the default class | The volume that keeps its identity |
| `cluster.resources` | 20m CPU, 64 MiB requested; 256 MiB limit | |
| `cluster.admission.enabled`, `.severity` | `false`, `medium` | [Warnings as workloads are applied](../usage/kubernetes.md#warnings-as-workloads-are-applied): a validating webhook in warn mode, with a certificate the chart makes |
| `server.nodeSelector`, `.tolerations`, `.affinity`, `.podAnnotations`, and the same for `agent` and `cluster` | | Scheduling and annotations |

## With Flux, Argo CD or a pipeline

The chart works the same from GitOps tools and CI/CD pipelines. Keep the values in Git, and keep secrets out of it:

- **The admin password** and **the agents' enrollment token** go in Kubernetes secrets that your secret tool creates, such as Sealed Secrets, SOPS or External Secrets. The values only name them (`server.admin.existingSecret`, `agent.enrollment.existingSecret`). If the chart is applied before the secret exists, the server waits for it and creates the account once the secret is mounted.
- **To upgrade**, change the chart's version in Git, after reading the [upgrade notes](../upgrade-notes/index.md). These tools render the chart from the new version's defaults plus your values every time, so there is no `--reuse-values` to think about.

The server's values, as on this page:

```yaml
server:
  admin:
    existingSecret: deaconguard-admin
```

### Flux

Flux takes the chart from GHCR with an `OCIRepository`, and installs it with a `HelmRelease`:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: deaconguard
  namespace: deaconguard
spec:
  interval: 1h
  url: oci://ghcr.io/cloudopsshell/charts/deaconguard
  ref:
    semver: "@RELEASE_MINOR@.x"   # patch releases come by themselves; or tag: "@RELEASE@"
  layerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: deaconguard
  namespace: deaconguard
spec:
  interval: 10m
  chartRef:
    kind: OCIRepository
    name: deaconguard
  values:
    server:
      admin:
        existingSecret: deaconguard-admin
```

To move to a new minor release, change `semver` (or `tag`) in Git. The agent DaemonSet is a second `OCIRepository` and `HelmRelease` in the agent's namespace, with the values from [the agents](#3-the-agents) (`server.enabled: false`, `agent.enabled: true`, `agent.enrollment.existingSecret`).

### Argo CD

Argo CD needs GHCR declared as a Helm repository with OCI, once, then an `Application`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: deaconguard-charts
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  name: deaconguard
  type: helm
  url: ghcr.io/cloudopsshell/charts
  enableOCI: "true"
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: deaconguard
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ghcr.io/cloudopsshell/charts
    chart: deaconguard
    targetRevision: "@RELEASE_MINOR@.*"   # patch releases come by themselves; or "@RELEASE@"
    helm:
      valuesObject:
        server:
          admin:
            existingSecret: deaconguard-admin
  destination:
    server: https://kubernetes.default.svc
    namespace: deaconguard
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

The chart is public, so the repository needs no credentials. Argo CD renders the chart with `helm template` and applies it, so `helm list` doesn't show the release; Argo CD does. The agent DaemonSet is a second `Application` with the agents' values.

### A pipeline

A CI/CD job (GitHub Actions, GitLab CI, Jenkins…) keeps the values in a file in its repository, and runs one command for the first install and every upgrade:

```bash
helm upgrade --install deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$VERSION" -n deaconguard --create-namespace -f deaconguard-values.yaml --wait
```

`-f` applies your file over the new chart's defaults each time, so the job needs neither `--reuse-values` nor `--reset-then-reuse-values`. Pin `VERSION` in the job, or read it from `https://get.deaconguard.io/stable.txt`.

## With Kustomize

The same server and agent are in [`deploy/kustomize`](https://github.com/Cloudopsshell/deaconguard/tree/main/deploy/kustomize), with the namespaces and their Pod Security labels:

```bash
kubectl create namespace deaconguard --save-config
kubectl -n deaconguard create secret generic deaconguard-admin --from-literal=password='a-long-password'
kubectl apply -k "https://github.com/Cloudopsshell/deaconguard/deploy/kustomize/server?ref=v$(curl -fsSL https://get.deaconguard.io/stable.txt)"

# after creating a reusable token for https://deaconguard.deaconguard.svc:8444
kubectl create namespace deaconguard-agent --save-config
kubectl -n deaconguard-agent create secret generic deaconguard-enrollment --from-literal=token='deaconguard1.…'
kubectl apply -k "https://github.com/Cloudopsshell/deaconguard/deploy/kustomize/agent?ref=v$(curl -fsSL https://get.deaconguard.io/stable.txt)"
```

To change them, use the directories as the base of your own overlay, with patches for the storage class, resources or node selection. [`examples/ingress-nginx.yaml`](https://github.com/Cloudopsshell/deaconguard/blob/main/deploy/kustomize/examples/ingress-nginx.yaml) is an Ingress for ingress-nginx and cert-manager.

## How the agent reads its node

The DaemonSet's pods:

- mount the node's `/` **read-only** at `/host`, and its `/tmp` writable at `/host/tmp` for the [advanced malware scan](../checks.md#the-advanced-antivirus-scan)'s rules;
- set `DEACONGUARD_HOST_ROOT=/host`, so every check runs in the node's root with the node's own tools. A check whose tool the node lacks reports that, as it would on the node itself;
- use the node's process list (`hostPID`) and network (`hostNetwork`, with `ClusterFirstWithHostNet` to resolve the Service);
- run as root, with every capability dropped except those the checks need: `SYS_CHROOT`, `DAC_READ_SEARCH`, `DAC_OVERRIDE`, `NET_ADMIN`, `AUDIT_CONTROL` and `SYS_PTRACE`; no privilege escalation, a read-only root filesystem, the runtime's default seccomp profile, and no service account token;
- report the node's name, from `DEACONGUARD_HOSTNAME`, and keep their identity in `/var/lib/deaconguard-agent` on the node, so a restarted or upgraded pod is the same host on the server.

A node's first pod enrolls with the token. If the server is replaced, say reinstalled with a new certificate, update the secret with a token from the new server and restart the DaemonSet: each pod enrolls with it. A pod also enrolls again when the server no longer knows it, so **removing a node's host on the server while its pod runs brings it back**; to stop scanning a node, keep the DaemonSet off it with `agent.nodeSelector` or `agent.affinity`, or [revoke the token](../usage/agents.md#reusable-tokens) first.

Don't run the DaemonSet on nodes that already have the agent installed as a package: each would enroll as its own host.

## Agents outside the cluster

Machines outside the cluster, such as virtual machines with the [install script](./install-script.md)'s agent, need a network path to the agent port. The server's Service is `ClusterIP`, inside the cluster only, so give agents a way in of their own. The dashboard stays inside either way:

| | Agent Service (any cluster) | Agent route (Traefik, chart 1.11.0 and later) |
| --- | --- | --- |
| Agents connect to | `https://ADDRESS:8444`, a load balancer of its own | `https://agents.example.com`, port 443, next to your other sites |
| Set | `server.agentService` | `server.agentRoute`: see [With Traefik](#with-traefik) |
| Who may connect | `loadBalancerSourceRanges`, and your firewall | your firewall |
| The Hosts page shows each agent | from its own address, with `externalTrafficPolicy: Local` | from Traefik's address |

Agents inside the cluster keep using `https://deaconguard.deaconguard.svc:8444`.

### With the agent Service

```yaml
# agent-service.yaml
server:
  agentService:
    enabled: true
    externalTrafficPolicy: Local      # record each agent's own address
    loadBalancerSourceRanges:         # the agents' addresses; empty allows everyone
      - 203.0.113.10/32
```

```bash
helm upgrade deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" -n deaconguard --reset-then-reuse-values \
  -f agent-service.yaml
kubectl -n deaconguard get svc deaconguard-agents
```

That adds the Service `deaconguard-agents`, a `LoadBalancer` with only port 8444. Its `EXTERNAL-IP` is the address for the machines' tokens, such as `https://203.0.113.50:8444`, or point a DNS name at it.

- **`loadBalancerSourceRanges`** is the list of addresses allowed to connect: your agents' public addresses, or your private network's range. A machine whose address isn't on it can't enroll (`context deadline exceeded`). Find a machine's public address with `curl -s https://api.ipify.org` on it. Limit 8444 in your provider's firewall too, and keep the NodePort range (30000–32767) closed there: `loadBalancerSourceRanges` doesn't cover it.
- **`externalTrafficPolicy: Local`** keeps each agent's own address. Without it, the cluster may rewrite connections to a node's address, and every host shows as `from 10.42.0.1` or another cluster address. It is the agent Service's own setting, separate from your ingress controller's, which covers the dashboard. Set it with one node, MetalLB or a cloud load balancer. With k3s's ServiceLB on several nodes, every node still accepts agents, but only those that connect to the node running the server pod are recorded with their own address; the others show ServiceLB's address on their node. Point the agents' address (or its DNS name) at the server's node for their own addresses. After changing it, restart the agents that were already connected (`sudo systemctl restart deaconguard-agent`): a connection opened before keeps the old address.
- **Keep it private.** Each provider has its own annotation for an internal load balancer, and its own firewall: [Reaching the agent port](../security/agent-network.md) has the values for your own data centre (k3s ServiceLB, MetalLB), Hetzner, AWS, Azure, Google Cloud, DigitalOcean, Akamai/Linode and Oracle Cloud, and what to do when the machines are in another data centre or only reachable over the internet.

### Other ways in

- **Through Traefik on port 443:** `server.agentRoute`; see [With Traefik](#with-traefik). Traefik passes TLS through and connects to the server itself, so the Hosts page shows Traefik's address for those agents.
- **Through another Ingress:** possible, but needs care. Agents check the server's certificate against the key in their token, or accept one their machine trusts for the server's name. So either pass the TLS connection through unchanged (ingress-nginx's `nginx.ingress.kubernetes.io/ssl-passthrough: "true"`, with passthrough turned on in the controller), or end TLS at the Ingress with a certificate the machines trust for its name. For the latter, allow request bodies of 80 MB (an agent's results can be that large; ingress-nginx allows 1 MB by default: `nginx.ingress.kubernetes.io/proxy-body-size: 80m`), and set `server.trustedProxies` to the ingress controller's network.
- **Without a load balancer:** `server.agentService.type=NodePort` and, from chart 1.10.0, a fixed `server.agentService.nodePort`, such as `30444`, open the agent port on every node. Enroll with a node's address and that port. `loadBalancerSourceRanges` doesn't apply to a node port, so your firewall is the only limit. Fine for a test cluster; in production, prefer a load balancer.

## Certificates and ingress

The server serves HTTPS itself. By default it creates a self-signed certificate on its first start, kept on its volume; agents trust it through the fingerprint in their token, and browsers warn about it once.

- **An Ingress for the dashboard:** set `server.ingress.*`, or start from the Kustomize example. The backend speaks HTTPS, so ingress-nginx needs `nginx.ingress.kubernetes.io/backend-protocol: HTTPS`. Set `server.trustedProxies` to the ingress controller's pod network, such as `10.42.0.0/16`, and limit who can reach it, for example with `nginx.ingress.kubernetes.io/whitelist-source-range`.
- **Your own certificate on the server:** put it in a `kubernetes.io/tls` secret and set `server.tls.existingSecret`. Agents accept the certificate whose key's fingerprint is in their token, or one their node trusts for the server's name. cert-manager gives a certificate a new key at each renewal by default, which agents enrolled before then don't know: set `privateKey.rotationPolicy: Never` on the Certificate, or keep the self-signed certificate on the server and put the trusted one on the Ingress.
- The dashboard's Ingress is for people. Agents use port 8444: inside the cluster through the Service, outside through the [agent load balancer](#agents-outside-the-cluster) or, with Traefik, the [agent route](#with-traefik).

### With Traefik

Traefik needs two things to reach the dashboard, which serves HTTPS itself: a `ServersTransport` and annotations on the Service. Without them it answers 404. From chart 1.11.0, `server.ingress.traefik.enabled` creates them, and can limit the dashboard to your addresses; `server.agentRoute` brings agents outside the cluster in on port 443 too, instead of a load balancer on 8444. This works with any Traefik 3 that has its CRDs (`traefik.io`). One step differs by how Traefik is installed, [keeping client addresses](#traefik-must-see-client-addresses); the rest is the same everywhere:

```yaml
server:
  trustedProxies:
    - 10.42.0.0/16                    # your pod network: see the table below
  ingress:
    enabled: true
    className: traefik
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod   # if you use cert-manager
      traefik.ingress.kubernetes.io/router.entrypoints: websecure
    hosts:
      - host: deaconguard.example.com
    tls:
      - secretName: deaconguard-dashboard-tls
        hosts: [deaconguard.example.com]
    traefik:
      enabled: true
      allowSourceRanges:              # who may open the dashboard; empty allows everyone
        - 203.0.113.10/32
  agentRoute:                         # optional: agents on https://agents.example.com
    enabled: true
    host: agents.example.com
    entryPoints: [websecure]          # your Traefik's HTTPS entry point
```

- **`server.ingress.traefik.enabled`** creates a `ServersTransport` (`<release>-tls`) and points the Service at it, so Traefik connects to the dashboard over HTTPS. It skips checking the server's certificate, which is its own; the connection stays in the cluster. Don't add these annotations by hand as well.
- **`allowSourceRanges`** adds an `ipAllowList` middleware (`<release>-allow`). Anyone else gets 403. `middlewares` adds others of your own, as `NAMESPACE-NAME@kubernetescrd`; don't name the allow list in a `router.middlewares` annotation yourself.
- **`trustedProxies`** is the network of Traefik's pods, so the server believes the client address Traefik passes on.
- **`agentRoute`** adds an `IngressRouteTCP` that passes TLS through unchanged, matched by the name agents connect to, so they still check the server's own key. Point a DNS name at Traefik and create tokens with `https://agents.example.com`, on port 443. Turn `server.agentService` off if you used it. With Cloudflare, keep the record **DNS only**: its proxy ends TLS, which the route can't pass through.

#### Traefik must see client addresses

Unless Traefik sees each client's own address, every request seems to come from a node: the allow list blocks everyone (403), sign-in limits apply to everyone at once, and the audit log shows one address. How to keep the address depends on how Traefik is installed:

| Your Traefik | What to change | `trustedProxies` | Entry point |
| --- | --- | --- | --- |
| [k3s or RKE2's own](#k3s-or-rke2) | A `HelmChartConfig` in `kube-system` | `10.42.0.0/16` | `websecure` |
| [Installed from Traefik's Helm chart](#traefiks-own-helm-chart) (on-premise, MetalLB, cloud) | Your Traefik values: `service.spec.externalTrafficPolicy: Local` | Your pod network, such as `10.244.0.0/16` (Flannel) or `192.168.0.0/16` (Calico) | `websecure`, or yours |
| [Behind another load balancer](#behind-another-load-balancer) (HAProxy, F5, a cloud NLB) | PROXY protocol on the load balancer and Traefik | Your pod network | Yours |

Check it: sign in, then open **Audit log**. Your sign-in should show your own address, not a `10.x` or other cluster address.

This is about **Traefik's** Service, which carries the dashboard and your other sites. Agents on the [agent Service](#with-the-agent-service) (port 8444) don't pass through Traefik: that Service has its own setting, `server.agentService.externalTrafficPolicy`. Set both if you use both.

##### k3s or RKE2

k3s installs Traefik itself; change its Service with a `HelmChartConfig`:

```yaml
# traefik-config.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    service:
      spec:
        externalTrafficPolicy: Local
```

```bash
kubectl apply -f traefik-config.yaml
kubectl -n kube-system get svc traefik -o jsonpath='{.spec.externalTrafficPolicy}{"\n"}'
```

k3s redeploys Traefik within a minute; the second command then prints `Local`. If you already have a `HelmChartConfig` named `traefik`, add `externalTrafficPolicy: Local` to its `valuesContent` instead. It applies to all your sites, which then see their visitors' addresses too.

##### Traefik's own Helm chart

When you installed Traefik yourself, with its chart (`oci://ghcr.io/traefik/helm/traefik`), set it in your Traefik values and upgrade that release:

```yaml
# your Traefik values
service:
  spec:
    externalTrafficPolicy: Local
```

```bash
helm upgrade traefik oci://ghcr.io/traefik/helm/traefik -n traefik --reuse-values -f traefik-values.yaml
```

With `Local`, only nodes that run a Traefik pod take the traffic: MetalLB announces the address from those nodes, and cloud load balancers send to those. Run Traefik on more than one node (`replicas: 2`, or `deployment.kind: DaemonSet`) so a node going down doesn't take the dashboard with it. Traefik on the host network (`hostNetwork: true`) sees client addresses already and needs no change.

##### Behind another load balancer

A TCP load balancer in front of Traefik (HAProxy, F5, a cloud network load balancer) hides the address itself. Turn on PROXY protocol (version 2) towards Traefik on the load balancer, and tell Traefik to trust it, in your Traefik values:

```yaml
ports:
  websecure:
    proxyProtocol:
      trustedIPs:
        - 10.0.0.5/32                 # your load balancer's addresses
```

On k3s, put the same `ports:` block in the `HelmChartConfig`'s `valuesContent`. Turn it on at both ends together: while the load balancer sends PROXY headers and Traefik doesn't expect them, every connection through it fails. Traefik reads the header only from the addresses in `trustedIPs`; connections from elsewhere work as before. On AWS, the load balancer controller turns PROXY protocol on with `service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: "*"` on Traefik's Service.

## Troubleshooting

| You see | Cause | Fix |
| --- | --- | --- |
| **404** on the dashboard | `server.ingress.traefik.enabled` is off, or a `router.middlewares` annotation names a middleware that doesn't exist | Turn it on; remove hand-written Traefik annotations from `server.service` and `server.ingress` |
| **403** on the dashboard, for everyone, you included | Traefik doesn't see client addresses | [Keep client addresses](#traefik-must-see-client-addresses) |
| The **Audit log** shows `10.x` addresses for sign-ins | The same | The same |
| **403** from your address only | It isn't in `allowSourceRanges` | Add it; find it with `curl -s https://api.ipify.org` |
| An agent's enrollment fails with `context deadline exceeded` | The machine's address isn't in `server.agentService.loadBalancerSourceRanges`, or a firewall blocks 8444 | Add its public address to both. On the machine, `curl -sk -o /dev/null -w '%{http_code}\n' https://ADDRESS:8444/agent/v1/job` prints `401` once it gets through; run the install command again |
| A host shows **from 10.42.0.1** (or another cluster address) | The agent Service rewrites addresses, or the agent's connection is older than the change | Set `server.agentService.externalTrafficPolicy: Local`, then `sudo systemctl restart deaconguard-agent` on the machine |
| A host shows **Traefik's address**, with `agentRoute` | Expected: Traefik passes TLS through and connects to the server itself | Use the agent Service if you need each agent's address |
| Agents can't connect through `agentRoute` | A proxied (orange) Cloudflare record, or a wrong entry point | Make the record DNS only; set `agentRoute.entryPoints` to your HTTPS entry point |

For a 404, Traefik's log names the missing object: `kubectl -n kube-system logs deploy/traefik` on k3s, or with your Traefik release's namespace.

## Commands

Server commands run in its pod, as its user:

```bash
kubectl -n deaconguard exec deaconguard-0 -- deaconguard user list
kubectl -n deaconguard exec -it deaconguard-0 -- deaconguard user passwd admin
kubectl -n deaconguard-agent logs daemonset/deaconguard-agent
```

Upgrade, back up and remove it as described in [Upgrade](./upgrade.md#helm), [Back up and restore](../usage/backup-and-restore.md#in-a-container) and [Uninstall](./uninstall.md#kubernetes).
