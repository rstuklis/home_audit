// HomeAuditRunner — gives the scheduled audit something macOS can grant
// Local Network access to.
//
// macOS Local Network privacy denies a background (launchd) job any connection
// to its own subnet unless the responsible program has been approved, and the
// approval is attached to a signed app. A LaunchAgent that runs /bin/zsh and an
// unsigned python has nothing to attach it to: the connection fails instantly
// with EHOSTUNREACH, no prompt is ever shown, and nothing appears in System
// Settings to switch on. A child process inherits the responsibility of the app
// that started it, so the agent runs this app and this app runs the audit.
//
// It will start exactly one thing: ~/.home_net_audit/run_audit.sh. It is not a
// general "run this with LAN access" tool, because anything could then borrow
// the permission by asking.
//
//   HomeAuditRunner                  run the scheduled audit wrapper
//   HomeAuditRunner --probe HOST     try one TCP connection to HOST port 80 from
//                                    a child process, print the result. This is
//                                    what makes macOS show the permission prompt.
import Foundation

func runChild(_ path: String, _ arguments: [String]) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = arguments
    do { try p.run() } catch {
        FileHandle.standardError.write("HomeAuditRunner: could not start \(path): \(error.localizedDescription)\n".data(using: .utf8)!)
        return 127
    }
    p.waitUntilExit()
    return p.terminationStatus
}

let args = Array(CommandLine.arguments.dropFirst())

if args.first == "--probe" {
    guard args.count == 2, args[1].allSatisfy({ $0.isNumber || $0 == "." }) else {
        FileHandle.standardError.write("usage: HomeAuditRunner --probe IPV4_ADDRESS\n".data(using: .utf8)!)
        exit(64)
    }
    // A child, not this process: the audit's connections are made by children,
    // so that is the case worth proving.
    let rc = runChild("/usr/bin/nc", ["-z", "-G", "3", args[1], "80"])
    print(rc == 0 ? "probe \(args[1]):80 -> OPEN" : "probe \(args[1]):80 -> BLOCKED or closed (nc exit \(rc))")
    exit(rc)
}

guard args.isEmpty else {
    FileHandle.standardError.write("HomeAuditRunner takes no arguments other than --probe.\n".data(using: .utf8)!)
    exit(64)
}

let wrapper = NSHomeDirectory() + "/.home_net_audit/run_audit.sh"
exit(runChild("/bin/zsh", [wrapper]))
