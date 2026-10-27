// Test-only: lets the Shared/ Swift code run on Linux, where App Groups do not exist.
import Foundation

#if os(Linux)
extension FileManager {
    func containerURL(forSecurityApplicationGroupIdentifier groupIdentifier: String) -> URL? {
        ProcessInfo.processInfo.environment["TINCMESH_CONTAINER"].map { URL(fileURLWithPath: $0, isDirectory: true) }
    }
}
#endif
