# TincMesh

A Tailscale-style iOS client for the [tinc](https://www.tinc-vpn.org) mesh VPN, running the **tinc 1.1pre18 pre-release** (SPTPS protocol 17.7) inside an iOS Network Extension. The UI is UIKit only, built in code with no storyboards and no SwiftUI.

TincMesh doesn't reimplement tinc. It embeds the real tinc daemon as a library, so it speaks to stock `tincd` 1.1 nodes on Linux, macOS, BSD and Windows, and it uses the same configuration files.

## Features

| | |
|---|---|
| **Device list** | Online and offline devices, their VPN addresses, and how traffic reaches each one: *Direct* (UDP, with round-trip time), *Relayed via X* (forwarded by another node, like Tailscale's DERP), or *TCP*. Searchable, with copy-on-tap addresses. |
| **One-tap connect** | A toggle in the navigation bar, plus *Always On* (VPN On Demand). |
| **Join with an invitation** | Paste or scan a QR code of a `tinc invite` URL. Keys are generated on the device, and `Ifconfig`/`Route` lines in the invitation become the interface address and routes. |
| **Invite devices** | Creates `tinc invite` URLs (shown as a QR code), optionally assigning the new device an IP. |
| **Create a network** | Sets up this device as the first node, like `tinc init`. |
| **Multiple networks** | Switch between them from the navigation bar menu. iOS runs one VPN at a time. |
| **Peer subnet routing** | Subnets announced by peers are routed automatically and updated live. You can opt in to an exit node, i.e. a peer announcing `0.0.0.0/0` or `::/0`. |
| **Rule-based routing** | Shadowrocket-style rules send chosen sites through chosen nodes, e.g. streaming through exit node X and work traffic through exit node Y. Supports domain, keyword and IP rules, fallback and fastest-node groups, REJECT, and live rule changes. See [Rule-based routing](#rule-based-routing). |
| **DNS** | Servers and search domains, with split DNS. |
| **Device details** | Endpoint, path MTU, hops, encryption state, traffic counters, public key, host file. |
| **Raw config access** | Edit `tinc.conf` and host files, import host files from Files or the clipboard, share your own host file. Edits are applied with a live reload. |
| **Log viewer** | tinc's own log, with selectable log levels. |
| **Network changes** | Switching between Wi‑Fi and cellular, or waking from sleep, triggers an immediate reconnect (`tinc retry`). |

## How it works

```
┌──────────────── TincMesh.app (UIKit) ───────────────┐
│ MeshViewController ─ NodeDetail ─ Settings ─ Join…   │
│ TunnelController (NETunnelProviderManager)           │
│ NetworkStore ── TincCore (keys, invite, join)        │
└───────────────┬──────────────────────────────────────┘
                │ App Group container: networks/<net>/{tinc.conf,hosts/,ed25519_key.priv,ios.json}
                │ sendProviderMessage: status / retry / reload
┌───────────────▼──── PacketTunnel.appex ──────────────┐
│ PacketTunnelProvider ── NEPacketTunnelNetworkSettings │
│   PacketBridge: NEPacketTunnelFlow ⇄ socketpair ⇄ ─┐  │
│   TincRunner: thread running tinc_ios_run()        │  │
│     └─ tinc 1.1pre18 event loop ◄── ios_device.c ◄─┘  │
│          meta (TCP) + SPTPS data (UDP) to peers       │
└───────────────────────────────────────────────────────┘
```

- **`TincCore/tinc/`** holds the unmodified tinc 1.1pre18 daemon sources, apart from two small patches (see [`patches/`](patches)): one disables the `Proxy = exec` option, because iOS forbids `system()`, and one adds a hook in `route.c` that lets a policy rule choose which node carries a packet. It is built without the legacy protocol, so there's no OpenSSL dependency. It uses tinc's own Ed25519, X25519 and ChaCha20-Poly1305 code, plus zlib from the iOS SDK.
- **`TincCore/ios/`** contains the iOS glue:
  - `tinc_ios.c` replaces `tincd.c`'s `main()`. It runs tincd on a thread and adds a control pipe so other threads can stop, retry, reload, or take a JSON status snapshot safely. tinc is single-threaded, and everything runs on its thread.
  - `ios_device.c` is a packet device on a `SOCK_DGRAM` socketpair carrying one raw IP packet per datagram. It's based on tinc's Android `fd_device.c`, and it only supports router mode.
  - `ios_control.c`, `ios_script.c` and `ios_process.c` stand in for the UNIX control socket, script execution and daemonizing, none of which is possible in an extension.
  - `tinc_join.c` and `tinc_invite.c` are ports of `tinc join` and `tinc invite`, without stdin prompts or `tinc-up` generation.
  - `policy.c` is the rule engine: it parses the rules, answers DNS inside the tunnel with stand-in addresses, translates addresses, and pins each connection to a node.
- **`ios.json`** holds what `tinc-up` does on other platforms: interface addresses, routes, DNS and MTU. If no address is set, this device's single-host `Subnet`s are used.

## Building

You need Xcode 15 or later, an Apple Developer account (Network Extensions don't run in the Simulator), and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

1. Edit `Config/Shared.xcconfig`: set `BUNDLE_ID_PREFIX` and `DEVELOPMENT_TEAM`.
2. In the Developer portal, enable the **Network Extensions** and **App Groups** capabilities for `<prefix>.tincmesh` and `<prefix>.tincmesh.PacketTunnel`, and create the group `group.<prefix>.tincmesh`. With automatic signing, Xcode can do this for you.
3. Generate the project and run it:
   ```sh
   xcodegen generate
   open TincMesh.xcodeproj
   ```
   Run the **TincMesh** scheme on a device.

## Using it with an existing tinc network

On any existing node that the phone can reach (normally a server with a public address):

```sh
tinc -n mynet invite phone
# Optionally add "Ifconfig = 10.0.0.7/24" and "Subnet = 10.0.0.7/32"
# to the invitation file before it is used, to hand out an address.
```

In TincMesh, tap **Join with Invitation** and paste or scan the URL.

You can also exchange host files manually: create a network in the app, share its host file to the server's `hosts/` directory, and import the server's host file under **Settings → Paste/Import Host File**.

Requirements and limits on the iOS side:
- Peers must run tinc **1.1**, because only the SPTPS protocol is built in. tinc 1.0 nodes and host files that only have RSA keys are not supported.
- Only `Mode = router` is supported. iOS has no layer-2 (TAP) tunnels.
- Scripts (`tinc-up`, `host-up`, `subnet-up`, …) don't run. Use the VPN interface settings instead.
- Unless a `Port` is set, the device listens on a random port, since phones are rarely reachable from outside. NAT traversal works as usual through UDP hole punching via other nodes.

## Rule-based routing

Open **Settings → Rules** for a network, turn on **Rule-Based Routing**, and edit `rules.conf`. The format is a subset of Shadowrocket/Surge configuration:

```ini
[General]
dns-server = 1.1.1.1            # resolver for names matched by a rule, queried through that rule's node
direct-dns-server = 1.1.1.1     # resolver for all other names, queried directly

[Proxy Group]
streaming = fallback, node_x, node_y    # first reachable node
auto = url-test, node_x, node_y         # lowest round trip, using tinc's own UDP probes

[Rule]
DOMAIN-SUFFIX,netflix.com,streaming
DOMAIN,github.com,node_y
DOMAIN-KEYWORD,google,auto
IP-CIDR,203.0.113.0/24,node_y
DOMAIN-SUFFIX,ads.example,REJECT
FINAL,DIRECT
```

A policy is a tinc node name, a group, `DIRECT` or `REJECT`. The first matching rule wins.

**How it works.** Names that match a rule are answered by a DNS responder inside the tunnel (`198.18.0.2`) with a stand-in address from `198.18.0.0/15`. The real address is looked up through the chosen node, so you get the answer the exit's location would get. Packets to a stand-in address are rewritten to the real address and sent to that node. Replies are rewritten back. Each connection stays on the node it started on, so two sites that share a CDN address can still use different exits. IP rules and `FINAL` apply to real addresses directly. Traffic that matches no rule never enters the tunnel, unless `FINAL` names a node.

**Exit nodes** (the machines that forward traffic to the Internet) run stock tinc and need:
- `Forwarding = kernel` in `tinc.conf`. Without it, a node that receives a packet for an Internet address forwards it by Subnet, so with several exits every packet ends up at the same one.
- IP forwarding (`sysctl -w net.ipv4.ip_forward=1`) and NAT for the VPN's addresses, e.g. `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE`.
- A route back into tinc for the VPN's addresses (the usual `tinc-up`).

**Limits.**
- Rules need an IPv4 VPN address. Routed names get IPv4 stand-in addresses only: their AAAA and HTTPS records are answered empty.
- `DIRECT` domain rules only bypass the tunnel when `FINAL` is `DIRECT`. Use `IP-CIDR …,DIRECT` to exclude addresses when `FINAL` names a node.
- `GEOIP`, `USER-AGENT`, `URL-REGEX`, `RULE-SET` and per-app rules aren't supported. They're reported as warnings and skipped.
- Apps that bypass system DNS (DNS-over-HTTPS, hard-coded addresses) only match IP rules.
- The first lookup through a node may take a second or two while tinc sets up encryption with it.

## Tests

The C core and the Swift `Shared/` layer are tested on Linux (or macOS) without Xcode. The tests drive the exact functions the app and extension call:

```sh
make -C tests check              # C core: needs cc and zlib
SWIFTC=/path/to/swiftc make -C tests check   # also compiles and runs Shared/*.swift
```

`tests/run_tests.sh` builds a three-node mesh on localhost and covers:
- Ed25519 key generation in tinc's file format.
- Invitation creation and joining, including single use and server-side key registration.
- ICMP through SPTPS: small packets and 1400-byte packets.
- Status snapshots, retry and reload, a clean stop, and restarting tinc in the same process (also checked under valgrind during development).
- A joined node reaching a peer it has no host file for, through the mesh.
- Rule-based routing with two exit nodes that resolve every name to the same address. The test checks that `a.test` leaves through `x` and `b.test` through `y`, along with suffix, keyword and IP rules, fallback and fastest groups, `REJECT`, direct lookups, live rule changes and status counters. The engine was also run under valgrind with no memory errors.
- The Swift `NetworkStore` doing create, invite, join and connect, plus rule validation and `MeshStatus` decoding.

The UIKit and NetworkExtension code needs Xcode to build.

## License

GPL-2.0-or-later, like tinc. See [COPYING](COPYING). tinc is © Ivo Timmermans, Guus Sliepen and others (see `TincCore/tinc/AUTHORS`). Distributing GPL software through the App Store raises licensing questions; consider this before publishing a build there.
