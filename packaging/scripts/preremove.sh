#!/bin/sh
# Stops the services when the package is removed, not when it is upgraded.
set -e
case "$1" in
	remove|purge|0)
		if [ -d /run/systemd/system ]; then
			systemctl disable --now deaconguard-agent.service deaconguard-server.service >/dev/null 2>&1 || true
		fi
		;;
esac
