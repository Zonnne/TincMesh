#!/bin/sh
# Integration tests for TincCore, the tinc 1.1 library embedded in the iOS app.
#
# Builds a three-node mesh on localhost, entirely through the TincCore API:
#   alpha  - "server" with a fixed address, configured by hand
#   beta   - configured by hand (exchanged host files), pings alpha
#   gamma  - joins via an invitation created by alpha (like a phone would)
# and checks end-to-end ICMP over SPTPS, invitations, status snapshots,
# retry/reload, stop, and restarting tinc inside one process.

set -eu
cd "$(dirname "$0")"

BUILD=build
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tincmesh-test.XXXXXX")
BASE_PORT=${BASE_PORT:-26655}
PIDS=""

cleanup() {
	for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM

fail() {
	echo "FAIL: $*"
	for log in "$WORK"/*.log; do
		[ -f "$log" ] || continue
		echo "---- $log (last 30 lines)"
		tail -n 30 "$log"
	done
	exit 1
}

pass() { echo "PASS: $*"; }

# make_node NAME IP PORT [CONNECTTO]
make_node() {
	dir="$WORK/$1"
	mkdir -p "$dir/hosts"
	{
		echo "Name = $1"
		echo "AddressFamily = ipv4"
		[ -n "${4:-}" ] && echo "ConnectTo = $4"
	} >"$dir/tinc.conf"
	pub=$("$BUILD/join_harness" keygen "$dir/ed25519_key.priv") || fail "keygen for $1"
	{
		echo "Address = 127.0.0.1"
		echo "Port = $3"
		echo "Subnet = $2/32"
		echo "Ed25519PublicKey = $pub"
	} >"$dir/hosts/$1"
}

echo "== building"
make -s all >/dev/null

echo "== key generation"
make_node alpha 10.99.0.1 "$BASE_PORT"
make_node beta 10.99.0.2 "$((BASE_PORT + 1))" alpha
cp "$WORK/alpha/hosts/alpha" "$WORK/beta/hosts/"
cp "$WORK/beta/hosts/beta" "$WORK/alpha/hosts/"
grep -q "BEGIN ED25519 PRIVATE KEY" "$WORK/alpha/ed25519_key.priv" || fail "private key format"
[ "$(stat -c %a "$WORK/alpha/ed25519_key.priv" 2>/dev/null || stat -f %Lp "$WORK/alpha/ed25519_key.priv")" = 600 ] || fail "private key mode"
pass "Ed25519 keys generated in tinc's format"

echo "== invitation"
URL=$("$BUILD/join_harness" invite "$WORK/alpha" gamma "127.0.0.1:$BASE_PORT" \
	"$(printf 'Ifconfig = 10.99.0.3/24\nRoute = 10.123.0.0/16\nSubnet = 10.99.0.3/32')") || fail "invite"
echo "$URL" | grep -Eq "^127\.0\.0\.1:$BASE_PORT/[A-Za-z0-9_-]{48}$" || fail "invitation URL format: $URL"
pass "invitation created: $URL"

"$BUILD/node_harness" responder "$WORK/alpha" "$WORK/alpha.log" 10.99.0.1 >"$WORK/alpha.out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 50); do grep -q "responder ready" "$WORK/alpha.out" && break; sleep 0.1; done
grep -q "responder ready" "$WORK/alpha.out" || fail "alpha did not start: $(cat "$WORK/alpha.out")"
pass "alpha running"

echo "== beta <-> alpha (hand-exchanged host files), with restart in-process"
"$BUILD/node_harness" ping "$WORK/beta" "$WORK/beta.log" 10.99.0.2 10.99.0.1 alpha --restart || fail "beta could not reach alpha"
pass "ICMP over SPTPS, status, retry, reload, stop and restart"

echo "== gamma joins with the invitation"
"$BUILD/join_harness" join "$WORK/gamma" "garbage/abc" 2>/dev/null && fail "accepted an invalid URL"
JSON=$("$BUILD/join_harness" join "$WORK/gamma" "$URL") || fail "join"
echo "  $JSON"
echo "$JSON" | python3 -c '
import json, sys
r = json.load(sys.stdin)
assert r["name"] == "gamma", r
assert r["netname"] == "testnet", r
assert r["ifconfig"] == ["10.99.0.3/24"], r
assert r["routes"] == ["10.123.0.0/16"], r
' || fail "join result"
grep -q "^Name = gamma" "$WORK/gamma/tinc.conf" || fail "gamma tinc.conf"
grep -q "^ConnectTo = alpha" "$WORK/gamma/tinc.conf" || fail "gamma ConnectTo"
grep -q "^Subnet = 10.99.0.3/32" "$WORK/gamma/hosts/gamma" || fail "gamma Subnet"
grep -q "^Ed25519PublicKey" "$WORK/gamma/hosts/gamma" || fail "gamma public key"
grep -q "^Ed25519PublicKey" "$WORK/gamma/hosts/alpha" || fail "alpha host file copied to gamma"
for _ in $(seq 30); do [ -f "$WORK/alpha/hosts/gamma" ] && break; sleep 0.1; done
grep -q "^Ed25519PublicKey" "$WORK/alpha/hosts/gamma" || fail "alpha learned gamma's key"
"$BUILD/join_harness" join "$WORK/gamma2" "$URL" 2>/dev/null && fail "invitation was reusable"
pass "invitation accepted, config written on both sides, single use enforced"

echo "== gamma -> alpha using the joined configuration"
"$BUILD/node_harness" ping "$WORK/gamma" "$WORK/gamma.log" 10.99.0.3 10.99.0.1 alpha || fail "gamma could not reach alpha"
pass "joined node reaches the mesh"

echo "== beta -> gamma through the mesh (gamma has no host file for beta)"
"$BUILD/node_harness" responder "$WORK/gamma" "$WORK/gamma2.log" 10.99.0.3 >"$WORK/gamma.out" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 50); do grep -q "responder ready" "$WORK/gamma.out" && break; sleep 0.1; done
"$BUILD/node_harness" ping "$WORK/beta" "$WORK/beta2.log" 10.99.0.2 10.99.0.3 gamma || fail "beta could not reach gamma"
python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
nodes = {n["name"]: n for n in s["nodes"]}
assert set(nodes) >= {"alpha", "beta", "gamma"}, nodes.keys()
g = nodes["gamma"]
assert g["reachable"] and "10.99.0.3" in g["subnets"], g
assert g["in_packets"] > 0 and g["out_packets"] > 0, g
assert any(e["from"] == "alpha" and e["to"] == "gamma" for e in s["edges"]), s["edges"]
print("  gamma via=%s udp_confirmed=%s pmtu=%d" % (g["via"], g["udp_confirmed"], g["mtu"]))
' "$WORK/beta/status.json" || fail "status JSON"
pass "three-node mesh, status JSON is valid"

echo "== rule-based routing: two exit nodes, per-site policies"
# x and y are exit nodes: both announce the whole IPv4 Internet.
make_node x 10.99.0.11 "$((BASE_PORT + 20))" alpha
make_node y 10.99.0.12 "$((BASE_PORT + 21))" alpha
make_node phone 10.99.0.20 "$((BASE_PORT + 22))" alpha
# Exit nodes hand everything they receive to their OS (which would NAT it to
# the Internet); otherwise tinc forwards by Subnet and both would pick x.
for n in x y; do
	echo "Subnet = 0.0.0.0/0" >>"$WORK/$n/hosts/$n"
	echo "Forwarding = kernel" >>"$WORK/$n/tinc.conf"
done
for n in x y phone; do
	cp "$WORK/$n/hosts/$n" "$WORK/alpha/hosts/"
	cp "$WORK/alpha/hosts/alpha" "$WORK/$n/hosts/"
done
for n in x y; do cp "$WORK/$n/hosts/$n" "$WORK/phone/hosts/"; done
"$BUILD/node_harness" exit "$WORK/x" "$WORK/x.log" 10.99.0.11 x >"$WORK/x.out" 2>&1 &
PIDS="$PIDS $!"
"$BUILD/node_harness" exit "$WORK/y" "$WORK/y.log" 10.99.0.12 y >"$WORK/y.out" 2>&1 &
PIDS="$PIDS $!"
"$BUILD/policy_harness" "$WORK/phone" "$WORK/phone.log" 10.99.0.20 "$((BASE_PORT + 30))" || fail "rule-based routing"
pass "domain, keyword, group and IP rules route through the chosen exit node; live rule changes"

echo "== Swift Shared/ layer (NetworkStore, TincConfigFile, MeshStatus) against TincCore"
SWIFTC=${SWIFTC:-$(command -v swiftc || true)}
if [ -z "$SWIFTC" ]; then
	echo "SKIP: no swiftc found (set SWIFTC=/path/to/swiftc)"
else
	"$SWIFTC" -swift-version 5 -module-name TincMeshShared -I ../TincCore/include \
		swift/main.swift swift/LinuxShims.swift ../Shared/*.swift \
		"$BUILD/libtinccore.a" -lz -o "$BUILD/shared_tests" || fail "compiling Shared/"
	C="$WORK/container"
	SPORT=$((BASE_PORT + 10))
	"$BUILD/shared_tests" "$C" unit || fail "Swift unit tests"
	"$BUILD/shared_tests" "$C" create "$SPORT" || fail "NetworkStore.create"
	"$BUILD/shared_tests" "$C" rules || fail "PolicyRules"
	SURL=$("$BUILD/shared_tests" "$C" invite "$SPORT" | head -1) || fail "NetworkStore.invite"
	"$BUILD/node_harness" responder "$C/networks/alpha" "$WORK/swift-alpha.log" 10.77.0.1 >"$WORK/swift-alpha.out" 2>&1 &
	PIDS="$PIDS $!"
	for _ in $(seq 50); do grep -q "responder ready" "$WORK/swift-alpha.out" && break; sleep 0.1; done
	"$BUILD/shared_tests" "$C" join "$SURL" || fail "NetworkStore.join"
	"$BUILD/node_harness" ping "$C/networks/alpha-2" "$WORK/swift-phone.log" 10.77.0.9 10.77.0.1 alpha || fail "joined network (created by Swift) cannot reach alpha"
	"$BUILD/shared_tests" "$C" status "$C/networks/alpha-2/status.json" || fail "MeshStatus decoding"
	pass "Swift Shared/ layer: create, invite, join, connect, rules, decode status"
fi

echo "ALL TESTS PASSED"
