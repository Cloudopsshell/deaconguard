#!/bin/sh
# Checks that the Helm chart upgrades every earlier release the way the
# Upgrade page tells people to: helm upgrade --reuse-values renders the new
# chart with the values of the release it upgrades, in place of the new
# values.yaml, so a template that reads a setting added since must still
# render. For each release tag with a chart, this renders the chart here with
# that release's values.yaml, as Helm does, for a server, an agent-only and a
# cluster-agent release, and with the Traefik options, and checks what comes
# out.
#
# Needs helm and the release tags (git fetch --tags).
set -eu

chart=deploy/helm/deaconguard
cmp -s "$chart/values.yaml" "$chart/files/defaults.yaml" || {
	echo "$chart/files/defaults.yaml must be a copy of values.yaml: cp $chart/values.yaml $chart/files/defaults.yaml" >&2
	exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

render() { # name, values file, helm --set options...
	name=$1 values=$2
	shift 2
	rm -rf "$work/chart"
	cp -R "$chart" "$work/chart"
	cp "$values" "$work/chart/values.yaml"
	if ! helm template deaconguard "$work/chart" -n deaconguard "$@" >"$work/out.yaml" 2>"$work/err"; then
		echo "FAIL $name: $(grep -m1 -i error "$work/err")" >&2
		return 1
	fi
}

expect() { # name, pattern, present|absent
	if grep -q "$2" "$work/out.yaml"; then found=present; else found=absent; fi
	if [ "$found" != "$3" ]; then
		echo "FAIL $1: expected $2 to be $3" >&2
		return 1
	fi
}

failed=0
cp "$chart/values.yaml" "$work/current.yaml"
releases="current $(git tag -l 'v*' | grep -v -- '-' | sort -V)"
for release in $releases; do
	values=$work/current.yaml
	if [ "$release" != current ]; then
		values=$work/$release.yaml
		git show "$release:$chart/values.yaml" >"$values" 2>/dev/null || continue
	fi
	ok=yes
	render "$release server" "$values" --set server.admin.existingSecret=deaconguard-admin &&
		expect "$release server" 'kind: StatefulSet' present &&
		expect "$release server" 'name: deaconguard-agents$' absent &&
		expect "$release server" 'kind: DaemonSet' absent || ok=no
	render "$release server with agent Service" "$values" --set server.agentService.enabled=true &&
		expect "$release server with agent Service" 'name: deaconguard-agents$' present || ok=no
	render "$release server with Traefik" "$values" --set server.ingress.enabled=true \
		--set 'server.ingress.hosts[0].host=deaconguard.example.com' --set server.ingress.traefik.enabled=true \
		--set 'server.ingress.traefik.allowSourceRanges={192.0.2.0/24}' \
		--set server.agentRoute.enabled=true --set server.agentRoute.host=agents.example.com &&
		expect "$release server with Traefik" 'kind: ServersTransport' present &&
		expect "$release server with Traefik" 'deaconguard-allow@kubernetescrd' present &&
		expect "$release server with Traefik" 'kind: IngressRouteTCP' present || ok=no
	render "$release agent only" "$values" --set server.enabled=false --set agent.enabled=true \
		--set agent.enrollment.existingSecret=deaconguard-enrollment &&
		expect "$release agent only" 'kind: DaemonSet' present &&
		expect "$release agent only" 'component: server' absent || ok=no
	render "$release cluster agent" "$values" --set server.enabled=false --set cluster.enabled=true \
		--set cluster.name=prod --set cluster.enrollment.existingSecret=deaconguard-cluster-enrollment &&
		expect "$release cluster agent" 'kind: ClusterRole' present || ok=no
	render "$release shared enrollment" "$values" --set server.enabled=false --set agent.enabled=true --set cluster.enabled=true \
		--set enrollment.existingSecret=shared-token &&
		expect "$release shared enrollment" 'secretName: shared-token' present &&
		expect "$release shared enrollment" 'secretName: deaconguard-enrollment' absent &&
		expect "$release shared enrollment" 'secretName: deaconguard-cluster-enrollment' absent || ok=no
	render "$release own enrollment kept" "$values" --set server.enabled=false --set agent.enabled=true --set cluster.enabled=true \
		--set enrollment.existingSecret=shared-token --set cluster.enrollment.existingSecret=cluster-only &&
		expect "$release own enrollment kept" 'secretName: cluster-only' present &&
		expect "$release own enrollment kept" 'secretName: shared-token' present || ok=no
	if [ "$ok" = yes ]; then echo "ok   upgrade from $release"; else failed=1; fi
done
exit "$failed"
