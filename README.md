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

- **`TincCore/tinc/`** holds the unmodified tinc 1.1pre18 daemon sources, apart from one patch (see [`patches/`](patches)): an `#ifdef` that disables the `Proxy = exec` option, because iOS forbids `system()`. It is built without the legacy protocol, so there's no OpenSSL dependency. It uses tinc's own Ed25519, X25519 and ChaCha20-Poly1305 code, plus zlib from the iOS SDK.
- **`TincCore/ios/`** contains the iOS glue:
  - `tinc_ios.c` replaces `tincd.c`'s `main()`. It runs tincd on a thread and adds a control pipe so other threads can stop, retry, reload, or take a JSON status snapshot safely. tinc is single-threaded, and everything runs on its thread.
  - `ios_device.c` is a packet device on a `SOCK_DGRAM` socketpair carrying one raw IP packet per datagram. It's based on tinc's Android `fd_device.c`, and it only supports router mode.
  - `ios_control.c`, `ios_script.c` and `ios_process.c` stand in for the UNIX control socket, script execution and daemonizing, none of which is possible in an extension.
  - `tinc_join.c` and `tinc_invite.c` are ports of `tinc join` and `tinc invite`, without stdin prompts or `tinc-up` generation.
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
- The Swift `NetworkStore` doing create, invite, join and connect, plus `MeshStatus` decoding.

The UIKit and NetworkExtension code needs Xcode to build.

## License

GPL-2.0-or-later, like tinc. See [COPYING](COPYING). tinc is © Ivo Timmermans, Guus Sliepen and others (see `TincCore/tinc/AUTHORS`). Distributing GPL software through the App Store raises licensing questions; consider this before publishing a build there.
