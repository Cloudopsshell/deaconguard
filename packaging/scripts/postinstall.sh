#!/bin/sh
# Creates the account the deaconguard-server service runs as. Neither service is
# enabled here: the agent needs enrolling first, and the server an account.
set -e
if ! getent passwd deaconguard >/dev/null 2>&1; then
	nologin=$(command -v nologin || echo /bin/false)
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --home-dir /var/lib/deaconguard --no-create-home --shell "$nologin" \
			--comment "DeaconGuard server" deaconguard
	elif command -v adduser >/dev/null 2>&1; then
		adduser --system --group --home /var/lib/deaconguard --no-create-home --shell "$nologin" deaconguard
	fi
fi
# The server's data directory, so accounts can be created before its first start.
if getent passwd deaconguard >/dev/null 2>&1; then
	install -d -o deaconguard -g deaconguard -m 0700 /var/lib/deaconguard
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# Pick up a new binary in services that are already running.
	systemctl try-restart deaconguard-agent.service deaconguard-server.service >/dev/null 2>&1 || true
fi
