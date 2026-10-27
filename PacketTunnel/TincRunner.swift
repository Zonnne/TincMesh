import CTinc
import Foundation

/// Runs tinc_ios_run() on a dedicated thread. tinc's event loop is single
/// threaded and owns all of its state; other threads talk to it only
/// through the thread-safe tinc_ios_stop/retry/reload/status calls.
final class TincRunner {
    private final class Callbacks {
        let onReady: () -> Void
        init(onReady: @escaping () -> Void) { self.onReady = onReady }
    }

    private let exited = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var finished = false

    var isFinished: Bool {
        lock.lock()
        defer { lock.unlock() }
        return finished
    }

    /// Starts tinc. `tunFD` is handed over to tinc, which closes it when done.
    /// `onReady` runs on the tinc thread once the network is up; `onExit` runs
    /// on the tinc thread after tinc_ios_run() returns, with its status.
    func start(confbase: URL, logURL: URL, tunFD: Int32, debugLevel: Int32,
               onReady: @escaping () -> Void, onExit: @escaping (Int32) -> Void) {
        let callbacks = Unmanaged.passRetained(Callbacks(onReady: onReady)).toOpaque()
        let confbasePath = confbase.path
        let logPath = logURL.path

        let thread = Thread { [weak self] in
            let status: Int32 = confbasePath.withCString { confbaseC in
                logPath.withCString { logC in
                    var options = tinc_ios_options(
                        confbase: confbaseC,
                        logfile: logC,
                        tun_fd: tunFD,
                        debug_level: debugLevel,
                        ready: { context in
                            guard let context else { return }
                            Unmanaged<Callbacks>.fromOpaque(context).takeUnretainedValue().onReady()
                        },
                        context: callbacks)
                    return tinc_ios_run(&options)
                }
            }
            Unmanaged<Callbacks>.fromOpaque(callbacks).release()
            if let self {
                self.lock.lock()
                self.finished = true
                self.lock.unlock()
                self.exited.signal()
            }
            onExit(status)
        }
        thread.name = "tinc"
        // tinc keeps several packet buffers (each up to MTU + overhead) on the stack.
        thread.stackSize = 4 << 20
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    /// Asks tinc to exit and waits for it. Returns false on timeout.
    @discardableResult
    func stop(timeout: TimeInterval = 5) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        // Repeat the request: a stop sent before the thread reaches tinc_ios_run() is a no-op.
        while !isFinished && Date() < deadline {
            tinc_ios_stop()
            if exited.wait(timeout: .now() + 0.1) == .success {
                exited.signal()
                return true
            }
        }
        return isFinished
    }

    func retry() {
        tinc_ios_retry()
    }

    func reload() {
        tinc_ios_reload()
    }

    /// The raw status JSON, or nil if tinc is not running. Blocks briefly.
    func statusJSON() -> Data? {
        guard let json = tinc_ios_status_json() else { return nil }
        defer { free(json) }
        return Data(bytes: json, count: strlen(json))
    }
}
