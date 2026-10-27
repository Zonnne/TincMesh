import Darwin
import Foundation
import NetworkExtension

/// Moves packets between NEPacketTunnelFlow and tinc.
///
/// tinc's device is one end of an AF_UNIX/SOCK_DGRAM socketpair (see
/// TincCore/ios/ios_device.c); this class owns the other end. Each
/// datagram is exactly one raw IPv4 or IPv6 packet, so no framing is needed.
final class PacketBridge {
    private let flow: NEPacketTunnelFlow
    private let appFD: Int32
    /// The end handed to tinc; ownership passes to tinc_ios_run().
    let tincFD: Int32

    private let queue = DispatchQueue(label: "tincmesh.packets", qos: .userInitiated)
    private var readSource: DispatchSourceRead?
    private let stateLock = NSLock()
    private var stopped = false

    private static let socketBufferSize: Int32 = 2 << 20
    private static let maxPacketSize = 65535
    private static let maxBatch = 64

    init(flow: NEPacketTunnelFlow) throws {
        self.flow = flow
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            throw TincMeshError("socketpair failed: \(String(cString: strerror(errno)))")
        }
        appFD = fds[0]
        tincFD = fds[1]

        // Darwin's default AF_UNIX datagram buffers are only a few KB.
        for fd in fds {
            var size = Self.socketBufferSize
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        }
        _ = fcntl(appFD, F_SETFL, fcntl(appFD, F_GETFL) | O_NONBLOCK)
    }

    func start() {
        let source = DispatchSource.makeReadSource(fileDescriptor: appFD, queue: queue)
        source.setEventHandler { [weak self] in self?.drainFromTinc() }
        let fd = appFD
        source.setCancelHandler { close(fd) }
        readSource = source
        source.resume()
        readFromSystem()
    }

    func stop() {
        stateLock.lock()
        stopped = true
        stateLock.unlock()
        readSource?.cancel()
        readSource = nil
    }

    private var isStopped: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stopped
    }

    /// Outbound: apps -> utun -> tinc.
    private func readFromSystem() {
        flow.readPackets { [weak self] packets, _ in
            guard let self, !self.isStopped else { return }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    // A full buffer means tinc is behind; drop like a congested link would.
                    _ = send(self.appFD, raw.baseAddress, raw.count, 0)
                }
            }
            self.readFromSystem()
        }
    }

    /// Inbound: tinc -> utun -> apps.
    private func drainFromTinc() {
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        var buffer = [UInt8](repeating: 0, count: Self.maxPacketSize)

        while packets.count < Self.maxBatch {
            let length = buffer.withUnsafeMutableBytes { recv(appFD, $0.baseAddress, $0.count, 0) }
            if length <= 0 { break }
            let version = buffer[0] >> 4
            guard version == 4 || version == 6 else { continue }
            packets.append(Data(buffer[0..<length]))
            protocols.append(NSNumber(value: version == 4 ? AF_INET : AF_INET6))
        }

        if !packets.isEmpty && !isStopped {
            flow.writePackets(packets, withProtocols: protocols)
        }
    }
}
