---
title: Reaching the agent port
description: How machines outside the server's network reach its agent port, 8444, safely, in a private network, across data centres or over the internet, with steps for Kubernetes and each major cloud.
---

Agents connect to the server's **agent port, 8444**. This page is about machines that aren't next to the server: in another network, another data centre or another cloud. It applies to every way of installing the server, and has steps for [Kubernetes](#kubernetes-the-agent-service) and for [each provider](#steps-for-each-provider).

## What agents need

- **Outbound TCP to port 8444 on the server.** Agents connect to the server; the server never connects to them, and agents listen on nothing. The machines you scan need no inbound port.
- **A direct connection.** Agents ignore HTTP proxy settings: each checks that the server's certificate matches the key in its enrollment token, which a proxy that ends TLS would break. Firewalls, NAT and load balancers that pass TCP through unchanged are fine.
- **A stable address.** The token carries the server's address, and agents keep using it. Use a static IP or, better, a DNS name you control, such as `agents.deaconguard.example.internal`, so the address can move without enrolling machines again. The certificate doesn't need to carry that name: agents check its key, not its name.

What already protects port 8444: it serves only the agent API, with no dashboard or sign-in page; a machine needs an enrollment token to enroll, and its own credential afterwards; every connection is TLS with the server's pinned key. What it doesn't do is keep the rest of the internet from reaching the port. That is the network's job, as below.

**Port 8443, the dashboard, is for people only.** Nothing on this page opens it; keep it private as in [Securing the dashboard](./securing-the-dashboard.md).

## Choose by where your machines are

| Your machines are | Do this |
| --- | --- |
| In the same cluster | Nothing: they use `https://deaconguard.deaconguard.svc:8444`. |
| In the same private network as the server (same VPC, VNet, data centre or private network) | [Same private network](#same-private-network) |
| In another network you can connect privately (another VPC, region, cloud or data centre) | Connect the networks, then as in the same private network: [Another data centre or cloud](#another-data-centre-or-cloud) |
| Only reachable over the internet | [Over the internet](#over-the-internet), locked down to their addresses |

## Same private network

1. **Give 8444 a private address only.** On Kubernetes, an [internal load balancer](#steps-for-each-provider) for the agent Service; on a VM, the server's private address.
2. **Allow 8444 only from your machines' networks** in the provider's firewall or security group, such as `10.0.0.0/16`. On Kubernetes, put the same ranges in `server.agentService.loadBalancerSourceRanges`.
3. **Enroll with the private address**, such as `https://10.0.12.34:8444`, so agents never leave your network.

## Another data centre or cloud

Prefer a **private path** between the networks over exposing 8444 to the internet. Then the agents' traffic is private end to end, and the steps are those of the [same private network](#same-private-network), with the other network's ranges allowed.

| Private path | Fits when |
| --- | --- |
| **Peering**: VPC peering (AWS, GCP), VNet peering (Azure), a shared Hetzner network | Both networks are in the same provider. |
| **A transit hub**: AWS Transit Gateway, Azure Virtual WAN, GCP Network Connectivity Center | Many networks in one provider. |
| **Site-to-site VPN** (IPsec, the provider's VPN gateway) or a dedicated link (Direct Connect, ExpressRoute, Cloud Interconnect) | Your data centre to a cloud, or cloud to cloud. |
| **WireGuard, or a mesh VPN such as Tailscale or NetBird** | A few machines anywhere, without network gear. Install it on the machines and on the server's nodes (or on a gateway in their network), and enroll with the server's address in that network. |

On GCP, an internal load balancer accepts clients from its own region only, unless you turn on global access (see [Google Cloud](#google-cloud-gke)).

## Over the internet

When there's no private path, 8444 can be public, locked down:

1. **Expose only 8444**, through a load balancer or address of its own (on Kubernetes, the [agent Service](#kubernetes-the-agent-service)). Never 8443.
2. **Allow only your machines' public addresses.** Give them fixed outbound addresses: a NAT gateway with a static IP, or the machines' own static IPs. Allow those, as `/32`s, in the provider's firewall in front of the server, and in `loadBalancerSourceRanges` too, and nothing from `0.0.0.0/0`. If a machine's address changes, it loses the server until you allow the new one, so fixed addresses matter.
3. **Use a DNS name** for the address in tokens, so you can move the server without enrolling again.
4. **Keep TLS end to end.** Don't put a proxy or an Ingress that ends TLS in front of 8444 (see [Through an Ingress](#through-an-ingress)).
5. **Hand out tokens carefully.** Prefer one-time tokens, which expire in 24 hours; give reusable ones a short lifetime, and revoke them when a rollout is done ([Enrollment tokens](../usage/agents.md#reusable-tokens)).
6. **Remove machines you no longer scan.** Removing a host revokes its agent's credential at once.
7. **Watch for change:** the **Agents** page shows each agent's last check-in, and the **Audit log** every enrollment.

## Kubernetes: the agent Service

On Kubernetes the server's Service, `deaconguard`, is `ClusterIP`: reachable inside the cluster only. For machines outside it, the chart (1.9.0 and later) adds a second Service with **only port 8444**, so the dashboard stays inside:

```yaml
server:
  agentService:
    enabled: true
    type: LoadBalancer
    port: 8444
    annotations: {}               # your provider's settings, as below
    loadBalancerSourceRanges:     # who may connect; empty means anyone
      - 10.0.0.0/16
    externalTrafficPolicy: Local  # record each agent's own address
    loadBalancerClass: ""         # which load balancer answers, if the cluster has several
    nodePort: ""                  # a fixed node port (30000-32767) instead of a random one
```

```bash
helm upgrade deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard \
  --version "$(curl -fsSL https://get.deaconguard.io/stable.txt)" -n deaconguard \
  --reset-then-reuse-values -f agent-service.yaml
kubectl -n deaconguard get svc deaconguard-agents
```

The Service is `deaconguard-agents`; its `EXTERNAL-IP` is the address for tokens (or point your DNS name at it). Agents inside the cluster keep using the `deaconguard` Service.

- **`loadBalancerSourceRanges`** is a standard Kubernetes field: the client addresses allowed to connect through the load balancer. It isn't a firewall of its own. Whatever runs the load balancer turns it into one: the cloud's firewall or security group in front of the load balancer (AWS, Azure, GCP, DigitalOcean), or packet filter rules on the nodes (k3s ServiceLB, and kube-proxy on most clusters). Not every provider honours it; the [steps for each provider](#steps-for-each-provider) say which, and what to use instead. Empty (`[]`) allows everyone.
- **The provider's own firewall still matters.** Set it as well, with the same ranges: it stops traffic before it reaches your network, and it doesn't change when someone edits the Helm values.
- **Every `LoadBalancer` Service also opens a NodePort** (30000–32767) on each node, which `loadBalancerSourceRanges` doesn't cover. Make sure your nodes' firewall doesn't allow that range from outside.
- **`externalTrafficPolicy`, `loadBalancerClass` and `nodePort`** (chart 1.10.0 and later) are standard Service settings, left to the cluster's defaults unless you set them:
  - `externalTrafficPolicy: Local` delivers connections only to the node the server runs on, so the server sees each agent's own address rather than a node's (`from 10.42.0.1` on the Hosts page). It's the agent Service's own setting, separate from your ingress controller's. With k3s's ServiceLB on several nodes, agents that connect to another node work, but show that node's ServiceLB address; see [With the agent Service](../installation/kubernetes.md#with-the-agent-service). Restart agents that were already connected after changing it.
  - `loadBalancerClass` picks which load balancer implementation creates the load balancer, when a cluster has more than one, such as MetalLB beside a cloud's own. It can't change once the Service exists.
  - `nodePort` fixes the node port that every `LoadBalancer` or `NodePort` Service opens, so a firewall rule or a token can name it and it doesn't change when you reinstall.
- **`server.ingress` is not for agents.** It routes only to the dashboard, 8443.

### Through an Ingress

**With Traefik** (k3s's ingress controller), the chart can do it from 1.11.0: `server.agentRoute` adds an `IngressRouteTCP` that passes TLS through unchanged, so agents connect to `https://agents.example.com` on port 443, next to your other sites, with no load balancer on 8444. The server then sees Traefik's address for those agents. See [With Traefik](../installation/kubernetes.md#with-traefik).

With other controllers, pass TLS through unchanged (ingress-nginx with `ssl-passthrough`), or end TLS there with a certificate the machines trust for its name. Details: [Agents outside the cluster](../installation/kubernetes.md#agents-outside-the-cluster).

## Steps for each provider

Each gives the `server.agentService` values, then what to set in the provider. Replace the ranges with your machines' networks. Settings marked *one-off* can't change once the load balancer exists: to change them, set `enabled: false`, upgrade, then set it back with the new value.

### Your own data centre or VMs

The cluster needs something that answers `LoadBalancer` Services:

- **k3s** has **ServiceLB** built in. It opens 8444 on the nodes' own addresses, and honours `loadBalancerSourceRanges`, also with `externalTrafficPolicy: Local`. Use a node's private address in tokens, or a DNS name for several. To keep it to some nodes, label them `svccontroller.k3s.cattle.io/enablelb=true`. To bring agents in through k3s's Traefik on port 443 instead, next to your other sites, see [Through an Ingress](#through-an-ingress).
- **MetalLB or kube-vip** gives the Service an address from a pool you set aside. Pick a pool on your private network. They don't filter clients themselves; kube-proxy applies `loadBalancerSourceRanges` on the nodes.

```yaml
server:
  agentService:
    enabled: true
    externalTrafficPolicy: Local          # each agent's own address
    loadBalancerSourceRanges: [10.20.0.0/16]
```

Then allow 8444 from the same ranges on your perimeter firewall (and the hosts' firewall, if they have one), and don't allow the NodePort range from outside. Machines in another site reach it over your site-to-site VPN.

Without `externalTrafficPolicy: Local`, the server sees connections as coming from a node (with MetalLB in layer 2 mode, the node that holds the address). With k3s's ServiceLB on several nodes, agents show their own address only when they connect to the server's node; see [With the agent Service](../installation/kubernetes.md#with-the-agent-service).

**Without a load balancer**, a fixed node port (chart 1.10.0 and later) opens the agent port on every node:

```yaml
server:
  agentService:
    enabled: true
    type: NodePort
    nodePort: 30444
```

Enroll with a node's address and that port, such as `https://10.20.0.11:30444`, or a DNS name that points at several nodes, and allow 30444 from your machines' networks. `loadBalancerSourceRanges` doesn't apply to a node port, so the firewall is the only limit.

### Hetzner Cloud

**k3s on a Hetzner server, with ServiceLB** (no Hetzner load balancer):

```yaml
server:
  agentService:
    enabled: true
    externalTrafficPolicy: Local          # each agent's own address
    loadBalancerSourceRanges:
      - 203.0.113.10/32                   # your servers' public addresses
      - 10.0.0.0/16                       # your Hetzner network, if you use one
```

- **Machines in Hetzner:** attach them and the k3s server to the same **Hetzner network**, and enroll with the k3s server's private address. Hetzner Cloud Firewalls don't filter traffic inside a private network, so the network itself is the boundary.
- **Machines elsewhere:** in the Hetzner console, add a **Cloud Firewall** to the k3s server that allows TCP 8444 only from their addresses, and doesn't allow 8443 or the NodePort range from the internet. Enroll with the server's public address or a DNS name for it.

**With the Hetzner Cloud Controller Manager** (`hcloud-cloud-controller-manager`), a Hetzner load balancer answers the Service. Keep it on your private network only:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      load-balancer.hetzner.cloud/location: fsn1
      load-balancer.hetzner.cloud/use-private-ip: "true"
      load-balancer.hetzner.cloud/disable-public-network: "true"
```

Hetzner's documentation doesn't say that its load balancers honour `loadBalancerSourceRanges`, and Cloud Firewalls attach to servers, not load balancers. So for machines outside Hetzner, prefer a VPN into the Hetzner network, or the ServiceLB setup above, over a public Hetzner load balancer.

### AWS (EKS)

With the **AWS Load Balancer Controller** installed, an internal Network Load Balancer:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: external            # one-off
      service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
      service.beta.kubernetes.io/aws-load-balancer-scheme: internal          # one-off
      service.beta.kubernetes.io/aws-load-balancer-target-group-attributes: preserve_client_ip.enabled=true
    loadBalancerSourceRanges: [10.0.0.0/16]
```

- The controller puts `loadBalancerSourceRanges` in the load balancer's security group. Without it, the default is `0.0.0.0/0`.
- `preserve_client_ip` lets the server see each agent's own address rather than the load balancer's.
- **Chart 1.10.0 and later:** instead of the `aws-load-balancer-type` annotation, you can set `loadBalancerClass: service.k8s.aws/nlb`, the controller's own class. Like the annotation, it can't change once the Service exists.
- **Other VPCs and accounts:** VPC peering or Transit Gateway, and add their ranges.
- **Over the internet:** `aws-load-balancer-scheme: internet-facing` with only your machines' addresses in `loadBalancerSourceRanges`. Don't change the scheme of an existing load balancer: set `enabled: false` first.

### Azure (AKS)

An internal Standard Load Balancer in the cluster's virtual network:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      service.beta.kubernetes.io/azure-load-balancer-internal: "true"
      # Optional: a subnet of its own in the same virtual network
      # service.beta.kubernetes.io/azure-load-balancer-internal-subnet: agents-subnet
    loadBalancerSourceRanges: [10.0.0.0/16]
```

- AKS applies `loadBalancerSourceRanges` in the cluster's network security group.
- **Other VNets:** VNet peering or Virtual WAN. **Other tenants or subscriptions without peering:** Private Link (`service.beta.kubernetes.io/azure-pls-create: "true"`), then a private endpoint in their network.
- **Over the internet:** leave out the `internal` annotation, and allow only your machines' addresses.

### Google Cloud (GKE)

An internal passthrough Network Load Balancer:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      networking.gke.io/load-balancer-type: "Internal"
      # Clients in other regions of the VPC, or connected networks:
      # networking.gke.io/internal-load-balancer-allow-global-access: "true"
    loadBalancerSourceRanges: [10.0.0.0/16]
```

- GKE turns `loadBalancerSourceRanges` into the source of the VPC firewall rule it creates for the Service. Without it, the rule allows every address.
- Without global access, only clients in the load balancer's region (and networks connected there) can reach it.
- **Other VPCs or projects:** VPC peering, Shared VPC or Network Connectivity Center. **Your data centre:** Cloud VPN or Cloud Interconnect.
- **Over the internet:** leave out the `Internal` annotation, and allow only your machines' addresses.

### DigitalOcean (DOKS)

An internal load balancer, reachable only from the cluster's VPC (DOKS 1.28.10-do.0 and later):

```yaml
server:
  agentService:
    enabled: true
    annotations:
      service.beta.kubernetes.io/do-loadbalancer-network: "INTERNAL"    # one-off
    loadBalancerSourceRanges: [10.10.0.0/16]
```

DOKS applies `loadBalancerSourceRanges` to the load balancer's firewall. **Over the internet:** leave out the annotation, and allow only your machines' addresses.

### Akamai / Linode (LKE)

A NodeBalancer, limited with its firewall:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      service.beta.kubernetes.io/linode-loadbalancer-firewall-acl: |
        {"allowList": {"ipv4": ["203.0.113.10/32", "198.51.100.0/24"]}}
```

Or attach a Cloud Firewall you manage yourself: `service.beta.kubernetes.io/linode-loadbalancer-firewall-id`. Linode's documentation doesn't say that NodeBalancers honour `loadBalancerSourceRanges`, so use the firewall.

### Oracle Cloud (OKE)

A private load balancer in the VCN:

```yaml
server:
  agentService:
    enabled: true
    annotations:
      service.beta.kubernetes.io/oci-load-balancer-internal: "true"     # one-off
    loadBalancerSourceRanges: [10.0.0.0/16]
```

For a network load balancer instead: `oci.oraclecloud.com/load-balancer-type: "nlb"` and `oci-network-load-balancer.oraclecloud.com/internal: "true"`. Allow 8444 from your machines' ranges in the load balancer subnet's security list or network security group; when OKE manages those rules for you, it opens the port from `0.0.0.0/0` unless the Service gives source ranges.

### Other providers

Look for three things in the provider's documentation for `LoadBalancer` Services: an annotation for an **internal or private** load balancer, whether it honours **`loadBalancerSourceRanges`** (or its own firewall annotation), and its **firewall** for the nodes or load balancer. Put the annotations in `server.agentService.annotations`.

## Servers outside Kubernetes

With the install script, packages or Docker Compose, the server listens on 8444 itself. The same rules apply: in the provider's firewall or security group, allow 8444 only from your machines' networks (or their public addresses), keep 8443 for people, and enroll with a private address or a DNS name. On AWS, for example: one rule for 8444 from your VPC's range, one for 8443 from your VPN range, nothing from `0.0.0.0/0`.

## Check it

From a machine that should reach the server:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://SERVER:8444/agent/v1/job
```

`401` means the port answers and wants an agent's credential: enrolling will work. A timeout means something in between blocks it.

From somewhere that shouldn't, such as your laptop on another network, the same command should time out. And `https://SERVER:8443` should not answer from your machines' networks at all, unless people use it from there.
