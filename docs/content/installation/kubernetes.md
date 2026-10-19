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
kubectl -n deaconguard create secret generic deaconguard-admin --from-literal=password='a-long-password'
helm install deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" \
  -n deaconguard --set server.admin.existingSecret=deaconguard-admin
```

The server creates the account `admin` with that password on its first start, and ignores the secret once any account exists. Open the dashboard:

```bash
kubectl -n deaconguard port-forward svc/deaconguard 8443:8443
```

and go to `https://127.0.0.1:8443`. The certificate is self-signed until you [give it one](#certificates-and-ingress).

### 2. A reusable token

On the **Agents** page, choose **Enroll a machine**, then **Many machines**. As the server address, use the Service's agent port:

```text
https://deaconguard.deaconguard.svc:8444
```

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

The agents check the nodes. To check the cluster too (its workloads, RBAC, namespaces, Kubernetes version and API server; see [Kubernetes clusters](../usage/kubernetes.md)), turn on the cluster agent. It runs as one unprivileged pod with a read-only ClusterRole that can't read secrets, and enrolls with a token like the agents (DeaconGuard 1.5.0 and later):

```bash
kubectl -n deaconguard-agent create secret generic deaconguard-cluster-enrollment --from-literal=token='deaconguard1.…'
helm upgrade deaconguard-agent oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" -n deaconguard-agent --reuse-values \
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
| `server.ingress.enabled`, `.className`, `.annotations`, `.hosts`, `.tls` | off | An Ingress for the dashboard |
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
| `server.nodeSelector`, `.tolerations`, `.affinity`, `.podAnnotations`, and the same for `agent` and `cluster` | | Scheduling and annotations |

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

## Certificates and ingress

The server serves HTTPS itself. By default it creates a self-signed certificate on its first start, kept on its volume; agents trust it through the fingerprint in their token, and browsers warn about it once.

- **An Ingress for the dashboard:** set `server.ingress.*`, or start from the Kustomize example. The backend speaks HTTPS, so ingress-nginx needs `nginx.ingress.kubernetes.io/backend-protocol: HTTPS`. Set `server.trustedProxies` to the ingress controller's pod network, such as `10.42.0.0/16`, and limit who can reach it, for example with `nginx.ingress.kubernetes.io/whitelist-source-range`.
- **Your own certificate on the server:** put it in a `kubernetes.io/tls` secret and set `server.tls.existingSecret`. Agents accept the certificate whose key's fingerprint is in their token, or one their node trusts for the server's name. cert-manager gives a certificate a new key at each renewal by default, which agents enrolled before then don't know: set `privateKey.rotationPolicy: Never` on the Certificate, or keep the self-signed certificate on the server and put the trusted one on the Ingress.
- Agents always connect to the Service's port 8444 directly, never through the Ingress.

## Commands

Server commands run in its pod, as its user:

```bash
kubectl -n deaconguard exec deaconguard-0 -- deaconguard user list
kubectl -n deaconguard exec -it deaconguard-0 -- deaconguard user passwd admin
kubectl -n deaconguard-agent logs daemonset/deaconguard-agent
```

Upgrade, back up and remove it as described in [Upgrade](./upgrade.md#helm), [Back up and restore](../usage/backup-and-restore.md#in-a-container) and [Uninstall](./uninstall.md#kubernetes).
