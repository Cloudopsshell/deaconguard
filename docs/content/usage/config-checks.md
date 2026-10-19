---
title: Dockerfiles and Kubernetes manifests
description: Check Dockerfiles, Containerfiles and Kubernetes manifests in a pipeline, before anything is built or deployed, against the Pod Security Standards and the NSA/CISA hardening guide.
---

`deaconguard config scan` checks the files that build and deploy containers, before anything is built or deployed: Dockerfiles (and Containerfiles), and Kubernetes manifests. It reads them as text, and builds, applies and runs nothing. It needs DeaconGuard 1.4.0 or later.

```bash
deaconguard config scan .
deaconguard config scan Dockerfile deploy/ --fail-on high
helm template shop ./chart | deaconguard config scan - --fail-on high
kubectl kustomize deploy/production | deaconguard config scan -
```

A folder is searched for `Dockerfile`, `Containerfile`, `Dockerfile.*`, `*.dockerfile`, `*.yaml` and `*.yml`; hidden folders, `node_modules` and `vendor` are left out. YAML files that aren't Kubernetes objects, such as CI workflows or Compose files, are skipped. `-` reads standard input.

**Helm charts** are templates, so render them first with `helm template`, with the values you deploy, and pipe the output in. A template file met in a folder is skipped, and the command says so.

## Output and failing the build

As for [images in pipelines](./ci-cd.md): `--fail-on critical|high|medium|low` exits with status **4** when a finding is at or above that severity, and `--format table|json|sarif|junit` with `--output FILE` writes a report. SARIF results point at the file and line, so GitHub code scanning shows them on the pull request's diff.

```text
Checked 3 files: 4 findings (1 critical, 2 high, 1 low)
  CRITICAL deploy/app.yaml:17 Deployment shop: container app is privileged [DG-K8S-001]
           A privileged container has every capability and the node's devices: it is root on the node. …
```

## Accepting a finding

Some findings are true and intended: a node agent needs the node's processes, for example. Accept them where they are, so the reason stays next to the file:

- **Kubernetes:** the annotation `deaconguard.io/ignore` on the object, or on its pod template, lists the rules to leave out:

  ```yaml
  metadata:
    annotations:
      deaconguard.io/ignore: "DG-K8S-002, DG-K8S-003"   # a node agent: reads the node's processes and files
  ```

- **Dockerfile:** a comment anywhere in it: `# deaconguard:ignore DG-DF-011`.
- **Everywhere:** `--skip DG-DF-011,DG-K8S-013` leaves rules out of one run.

## Rules

`deaconguard config rules` lists them. The Kubernetes rules follow the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (baseline, then restricted) and the NSA/CISA Kubernetes Hardening Guidance (version 1.2); the Dockerfile rules, Docker's build best practices. Each finding says how to fix it. Secret values are never shown, only their names.

### Dockerfiles

Only the last stage becomes the image, so the user and health check are checked there; every stage's base image is checked.

| Rule | Severity | Finding |
| --- | --- | --- |
| `DG-DF-001` | High | The image runs as root |
| `DG-DF-002` | Medium | The base image isn't pinned to a version |
| `DG-DF-003` | High | A secret is set in the image |
| `DG-DF-004` | Medium | A script is downloaded and run without being checked |
| `DG-DF-005` | Medium | ADD downloads a file from a URL |
| `DG-DF-006` | Low | ADD copies local files; COPY is clearer |
| `DG-DF-007` | Medium | The image uses sudo |
| `DG-DF-008` | Medium | The image exposes SSH |
| `DG-DF-009` | Medium | Files are made writable by everyone |
| `DG-DF-010` | Low | No .dockerignore: the build context may include secrets |
| `DG-DF-011` | Low | No HEALTHCHECK |

### Kubernetes

Pods and the workloads that run them (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, ReplicationController, and Lists of them), and RBAC roles and bindings. A running cluster gets more checks, such as namespaces without network policies and the Kubernetes version: see [Kubernetes clusters](./kubernetes.md). A privileged container gets `DG-K8S-001` rather than the capability and privilege-escalation findings it implies. Rules that match a DISA Kubernetes STIG rule name it; see [Kubernetes clusters](./kubernetes.md#rules-for-clusters).

| Rule | Severity | Finding | Source | DISA STIG |
| --- | --- | --- | --- | --- |
| `DG-K8S-001` | Critical | A container is privileged | Pod Security Standards (baseline) |  |
| `DG-K8S-002` | High | The pod shares the node's network, process or IPC namespace | Pod Security Standards (baseline) |  |
| `DG-K8S-003` | High | The pod mounts a folder of the node (hostPath) | Pod Security Standards (baseline) |  |
| `DG-K8S-004` | High | A container adds a dangerous Linux capability | Pod Security Standards (baseline) |  |
| `DG-K8S-005` | Medium | A container uses a port on the node (hostPort) | Pod Security Standards (baseline) | V-242414 |
| `DG-K8S-006` | High | A container turns off seccomp, AppArmor or /proc masking | Pod Security Standards (baseline) |  |
| `DG-K8S-007` | Medium | A container may gain more privileges than its process has | Pod Security Standards (restricted) |  |
| `DG-K8S-008` | Medium | A container may run as root | Pod Security Standards (restricted) |  |
| `DG-K8S-009` | High | A container runs as root (runAsUser: 0) | Pod Security Standards (restricted) |  |
| `DG-K8S-010` | Low | A container keeps Linux capabilities it doesn't drop | Pod Security Standards (restricted) |  |
| `DG-K8S-011` | Low | No seccomp profile is set | Pod Security Standards (restricted) |  |
| `DG-K8S-012` | Low | A container's root file system is writable | NSA/CISA Hardening Guide |  |
| `DG-K8S-013` | Low | A container has no memory limit | NSA/CISA Hardening Guide |  |
| `DG-K8S-014` | Medium | A container image isn't pinned to a version | NSA/CISA Hardening Guide |  |
| `DG-K8S-015` | High | A secret is written into the manifest | NSA/CISA Hardening Guide | V-274883 |
| `DG-K8S-016` | Low | The pod gets a service account token it may not need | NSA/CISA Hardening Guide |  |
| `DG-K8S-020` | High | A binding grants cluster-admin | RBAC good practices |  |
| `DG-K8S-021` | High | A role grants every action on every resource | RBAC good practices |  |
| `DG-K8S-022` | Medium | A role can read secrets | RBAC good practices | V-274884 |
| `DG-K8S-023` | High | A role can escalate privileges | RBAC good practices |  |
