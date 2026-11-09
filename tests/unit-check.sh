#!/bin/sh
# The packaged systemd units (packaging/): the system unit runs mod-host as its own system user in the audio group,
# with the hardening that fits a JACK client, and the user unit is a unit a user manager can run (no User=). The spec
# installs each where it belongs and declares the user. A planted copy without User= runs first and must be refused,
# so the check cannot pass vacuously.
#
#   sh tests/unit-check.sh      exit 0 conforms, 1 an offence (named), 2 the planted copy was not refused
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)

check() { # <system unit> <user unit> <spec> <sysusers>
	sys=$1 usr=$2 spec=$3 users=$4 bad=0
	for line in 'User=mod-host' 'Group=mod-host' 'SupplementaryGroups=audio' 'NoNewPrivileges=yes' \
		'ProtectSystem=strict' 'ProtectHome=read-only' 'PrivateTmp=yes' 'StateDirectory=mod-host' \
		'ReadWritePaths=/var/lib/mod-host' 'LimitRTPRIO=95' 'LimitMEMLOCK=infinity'; do
		grep -qx "$line" "$sys" 2>/dev/null || { echo "  the system unit lacks $line"; bad=1; }
	done
	grep -q '^User=' "$usr" 2>/dev/null && { echo "  the user unit sets User=, which a user manager refuses"; bad=1; }
	grep -q '^ExecStart=/usr/bin/mod-host' "$usr" 2>/dev/null || { echo "  the user unit does not start mod-host"; bad=1; }
	grep -q '^u mod-host ' "$users" 2>/dev/null || { echo "  the sysusers file declares no user mod-host"; bad=1; }
	grep -q '^m mod-host audio$' "$users" 2>/dev/null || { echo "  the sysusers file does not put mod-host in audio"; bad=1; }
	grep -q 'packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service' "$spec" ||
		{ echo "  the spec does not install the system unit"; bad=1; }
	grep -q 'packaging/%{name}.user.service %{buildroot}%{_userunitdir}/%{name}.service' "$spec" ||
		{ echo "  the spec does not install the user unit as the user's"; bad=1; }
	grep -q '^%{_sysusersdir}/%{name}.conf$' "$spec" || { echo "  the spec does not ship the sysusers file"; bad=1; }
	return $bad
}

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
P=$ROOT/packaging
if [ -f "$P/mod-host.service" ]; then
	grep -v '^User=' "$P/mod-host.service" > "$tmp/planted.service"
	if check "$tmp/planted.service" "$P/mod-host.user.service" "$P/mod-host.spec" "$P/mod-host.sysusers" >/dev/null; then
		echo "NOT A RESULT: a system unit without User= was not refused"
		exit 2
	fi
fi
check "$P/mod-host.service" "$P/mod-host.user.service" "$P/mod-host.spec" "$P/mod-host.sysusers" || exit 1
# what systemd itself says of the system unit's sandbox, where it is installed (informative)
if command -v systemd-analyze >/dev/null 2>&1; then
	systemd-analyze security --offline=yes "$P/mod-host.service" 2>/dev/null | tail -n 1 || :
fi
echo "unit-check: the system unit runs as mod-host in audio, hardened; the user unit runs as its user"
