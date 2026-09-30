#!/bin/sh
# Creates the account the opsarmor-server service runs as. Neither service is
# enabled here: the agent needs enrolling first, and the server an account.
set -e
if ! getent passwd opsarmor >/dev/null 2>&1; then
	nologin=$(command -v nologin || echo /bin/false)
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --home-dir /var/lib/opsarmor --no-create-home --shell "$nologin" \
			--comment "OpsArmor server" opsarmor
	elif command -v adduser >/dev/null 2>&1; then
		adduser --system --group --home /var/lib/opsarmor --no-create-home --shell "$nologin" opsarmor
	fi
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# Pick up a new binary in services that are already running.
	systemctl try-restart opsarmor-agent.service opsarmor-server.service >/dev/null 2>&1 || true
fi
