# OpsArmor Helm chart

This chart runs the OpsArmor CLI as one Kubernetes CronJob per configured remote host. It is for scheduled scans from a cluster, not a dashboard or a multi-user server. The chart is disabled by default; set a schedule and provide explicit host profiles, an existing SSH key Secret, and independently verified SSH host keys to enable it.

The controller Pods are non-root with a read-only root filesystem. SSH private keys are mounted read-only from a pre-created Kubernetes Secret and are never included in the chart or ConfigMap. Host fingerprints must be verified before installation because CronJobs cannot interactively enroll unknown keys. Each target gets its own PVC for reports and cached official advisory feeds.

Create a Secret with the private key file referenced by each host's `keyFile`:

```sh
kubectl create secret generic opsarmor-ssh-keys \
  --from-file=id_ed25519="$HOME/.ssh/id_ed25519"
```

Copy [values.example.yaml](values.example.yaml), replace example hosts and known-host keys with authorized targets and fingerprints verified through a trusted channel, then install:

```sh
helm upgrade --install opsarmor ./charts/opsarmor \
  --namespace opsarmor --create-namespace \
  -f my-opsarmor-values.yaml
```

The `knownHosts` entries are public host keys, not private credentials. Do not use `ssh-keyscan` output as identity verification by itself. The cluster must have egress to the authorized SSH targets and the relevant official advisory feeds. Configure a NetworkPolicy and restrict outbound SSH to approved destinations in production.

To package a chart locally:

```sh
helm package ./charts/opsarmor --destination dist
```