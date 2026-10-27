// Exercises the app's Shared/ Swift layer against the real TincCore C library.
//
// Usage: shared_tests <container-dir> <step> [args]
//   unit                       pure Swift tests (config parsing, CIDR math)
//   create <port>              create network "alpha" through NetworkStore
//   invite <port>              print an invitation URL for "phone" from alpha
//   join <url>                 join with NetworkStore (as the app does)
//   status <status.json>       decode a tinc status snapshot with MeshStatus
import Foundation

var failures = 0

func check(_ condition: @autoclosure () -> Bool, _ message: String, line: Int = #line) {
    if !condition() {
        print("  FAILED (line \(line)): \(message)")
        failures += 1
    }
}

func unitTests() {
    var config = TincConfigFile(text: """
    # comment
    Name = phone
    ConnectTo=server1
    connectto   server2
    Subnet = 10.1.0.0/16#5

    -----BEGIN ED25519 PUBLIC KEY-----
    Name = notAKey
    -----END ED25519 PUBLIC KEY-----
    """)
    check(config.value("name") == "phone", "case-insensitive lookup")
    check(config.values("ConnectTo") == ["server1", "server2"], "all = forms parse: \(config.values("ConnectTo"))")
    check(config.values("Name") == ["phone"], "PEM block contents are ignored")
    config.setAll("ConnectTo", ["a", "b", "c"])
    check(config.values("ConnectTo") == ["a", "b", "c"], "setAll replaces")
    check(config.text.contains("ConnectTo = a\nConnectTo = b\nConnectTo = c\nSubnet"), "setAll keeps position:\n\(config.text)")
    config.append("Port", "655")
    check(config.text.contains("Port = 655\n-----BEGIN"), "append goes before PEM block")
    config.set("Port", nil)
    check(config.value("Port") == nil && config.text.hasPrefix("# comment\n"), "remove keeps comments")
    check(TincConfigFile.isValidNodeName("node_1") && !TincConfigFile.isValidNodeName("my-node"), "node names")

    let r = IPAddressRange("10.20.30.40/22")!
    check(r.network.description == "10.20.28.0/22", "network: \(r.network)")
    check(r.subnetMaskString == "255.255.252.0", "mask: \(r.subnetMaskString)")
    check(IPAddressRange("10.1.2.3")?.isSingleHost == true, "single host")
    check(IPAddressRange("10.1.0.0/16#10")?.prefix == 16, "tinc weight suffix")
    check(IPAddressRange("fd00:1:2::5/48")?.network.description == "fd00:1:2::/48", "v6 /48")
    check(IPAddressRange("fd00:1:2::5/36")?.network.description == "fd00:1::/36", "v6 /36: \(IPAddressRange("fd00:1:2::5/36")!.network)")
    check(IPAddressRange("0.0.0.0/0")?.isDefaultRoute == true, "default route")
    check(IPAddressRange("00:11:22:33:44:55") == nil, "MAC subnets rejected")
    check(IPAddressRange("10.0.0.1/33") == nil, "bad prefix rejected")
    check(NetworkStore.isValidNetName("home-vpn.1") && !NetworkStore.isValidNetName("a/b") && !NetworkStore.isValidNetName(".x"), "netnames")

    var settings = TunnelSettings()
    settings.dnsServers = ["10.0.0.53"]
    let data = try! JSONEncoder().encode(settings)
    check(try! JSONDecoder().decode(TunnelSettings.self, from: data) == settings, "settings round trip")
    check((try? JSONDecoder().decode(TunnelSettings.self, from: Data("{\"mtu\":1300}".utf8)))?.mtu == 1300, "partial settings decode")
}

let args = CommandLine.arguments
guard args.count >= 3 else {
    print("usage: shared_tests <container> <step> [args]")
    exit(2)
}
setenv("TINCMESH_CONTAINER", args[1], 1)
let store = NetworkStore.shared

switch args[2] {
case "unit":
    unitTests()

case "create":
    let port = Int(args[3])!
    let network = try! store.create(.init(netname: "alpha", nodeName: "alpha", address: IPAddressRange("10.77.0.1/24")!,
                                          publicAddress: "127.0.0.1", port: port, connectTo: []))
    check(network.validate() == nil, "valid: \(network.validate() ?? "")")
    check(network.nodeName == "alpha", "Name")
    let host = network.loadHost("alpha")!
    check(host.value("Subnet") == "10.77.0.1", "Subnet: \(host.text)")
    check(host.value("Ed25519PublicKey") == TincCore.publicKey(privateKeyURL: network.privateKeyURL), "public key matches private key")
    check(network.interfaceAddresses(network.loadSettings()).map(\.description) == ["10.77.0.1/24"], "interface address")
    check(network.loadSettings().routes == ["10.77.0.0/24"], "network route")
    check(store.networks().map(\.name) == ["alpha"], "listed")
    check((try? store.create(.init(netname: "alpha", nodeName: "x", address: r10(), publicAddress: nil, port: nil, connectTo: []))) == nil, "duplicate rejected")
    // Add a peer host file the way a user would paste one.
    try! store.importHost(name: "server", contents: "Address = 192.0.2.1\nSubnet = 10.77.5.0/24\nEd25519PublicKey = \(host.value("Ed25519PublicKey")!)\n", into: network)
    check(network.staticRoutes(network.loadSettings()).map(\.description).sorted() == ["10.77.0.0/24", "10.77.5.0/24"], "static routes include peer subnets")
    check((try? store.importHost(name: "nokey", contents: "Address = 1.2.3.4\n", into: network)) == nil, "host without key rejected")
    try! store.removeHost(name: "server", from: network)

case "invite":
    let network = store.network(named: "alpha")!
    let url = try! store.invite(network: network, invitee: "phone", address: "127.0.0.1:\(args[3])",
                                vpnAddress: IPAddressRange("10.77.0.9/24"))
    print(url)

case "join":
    do {
        let network = try store.join(invitation: args[3], netname: nil)
        check(network.name == "alpha-2", "netname from invitation, made unique: \(network.name)")
        check(network.nodeName == "phone", "Name")
        check(network.validate() == nil, "valid: \(network.validate() ?? "")")
        let settings = network.loadSettings()
        check(settings.addresses == ["10.77.0.9/24"], "Ifconfig became an interface address: \(settings.addresses)")
        check(network.loadConfig()?.values("ConnectTo") == ["alpha"], "ConnectTo")
        check(network.hostNames() == ["alpha", "phone"], "hosts: \(network.hostNames())")
        check(store.networks().count == 2, "two networks")
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: AppGroup.networksURL.path).filter { $0.hasPrefix(".join") }
        check(leftovers.isEmpty, "staging directory cleaned up")
    } catch {
        check(false, "join failed: \(error.localizedDescription)")
    }
    check((try? store.join(invitation: "127.0.0.1:1/" + String(repeating: "A", count: 48), netname: nil)) == nil, "bad invitation fails")

case "rules":
    let network = store.network(named: "alpha")!
    // The template must be valid as shipped.
    let template = try! TincCore.checkRules(PolicyRules.template)
    check(template.rules == 0 && template.final == "DIRECT" && !template.captureAllDns, "template is valid: \(template)")

    var settings = network.loadSettings()
    settings.dnsServers = ["10.77.0.53"]
    settings.searchDomains = ["corp"]
    let text = """
    [Proxy Group]
    media = fallback, node_x, node_y
    [Rule]
    DOMAIN-SUFFIX,netflix.com,media
    IP-CIDR,203.0.113.0/24,node_y
    IP-CIDR,192.0.2.0/24,DIRECT
    FINAL,node_x
    """
    let effective = PolicyRules.effectiveText(text, settings: settings)
    check(effective.hasPrefix(text) && effective.contains("mesh-dns-server = 10.77.0.53") && effective.contains("mesh-domains = corp"),
          "mesh DNS appended after the user's rules:\n\(effective)")
    let summary = try! TincCore.checkRules(effective)
    check(summary.matchDomains == ["netflix.com", "corp"], "split DNS domains: \(summary.matchDomains)")
    check(summary.captureAllDns && summary.defaultRoute, "FINAL through a node captures DNS and the default route")
    check(summary.includeRoutes == ["203.0.113.0/24"] && summary.excludeRoutes == ["192.0.2.0/24"], "routes: \(summary)")
    check(summary.groups == ["media"] && summary.nodes.sorted() == ["node_x", "node_y"], "groups and nodes")
    do {
        _ = try TincCore.checkRules("[Rule]\nDOMAIN,a.test,bad name\n")
        check(false, "invalid rules accepted")
    } catch {
        check(error.localizedDescription.hasPrefix("Line 2:"), "error has line number: \(error.localizedDescription)")
    }

    try! Data(text.utf8).write(to: network.rulesURL)
    settings.rulesEnabled = false
    check(network.activeRules(settings) == nil, "no rules when disabled")
    settings.rulesEnabled = true
    check(network.activeRules(settings) == effective, "active rules when enabled")
    try! FileManager.default.removeItem(at: network.rulesURL)

    let live = MeshStatus.decode(Data("""
    {"version":"1.1pre18","name":"a","port":"1","now":1,"nodes":[],"edges":[],"connections":[],
     "policy":{"enabled":true,"rules":3,"flows":2,"fake_ips":1,"dns_pending":0,"dns_queries":5,"dns_fake":1,
               "dns_direct":4,"dns_rejected":0,"dns_failed":0,"routed_packets":9,"rejected_packets":0,
               "groups":[{"name":"media","selected":"node_x"},{"name":"b","selected":null}]}}
    """.utf8))
    check(live?.policy?.flows == 2 && live?.policy?.groups?.first?.selected == "node_x" && live?.policy?.groups?.last?.selected == nil,
          "policy status decodes")

case "status":
    let data = try! Data(contentsOf: URL(fileURLWithPath: args[3]))
    guard let status = MeshStatus.decode(data) else {
        check(false, "MeshStatus did not decode")
        break
    }
    check(status.myself?.path == .myself, "myself")
    let peers = status.nodes.filter { !$0.myself }
    check(!peers.isEmpty && peers.allSatisfy { $0.path != .offline }, "peers online: \(peers.map { "\($0.name)=\($0.path)" })")
    for peer in peers {
        print("  \(peer.name): \(peer.path), subnets \(peer.ipSubnets.map(\.description))")
    }

default:
    print("unknown step")
    exit(2)
}

func r10() -> IPAddressRange { IPAddressRange("10.0.0.1/24")! }

if failures > 0 {
    print("\(failures) check(s) failed")
    exit(1)
}
print("ok: \(args[2])")
