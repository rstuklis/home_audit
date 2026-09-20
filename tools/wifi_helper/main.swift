// HomeAuditWiFi — reads the connected Wi-Fi name for home_net_audit.py.
//
// macOS withholds the SSID and every BSSID from a process without Location
// Services access, and Terminal never asks for that access, so it cannot be
// added to the list by hand. An app that asks for itself can be. This is that
// app and nothing more: it requests the permission, reads the Wi-Fi interface
// through CoreWLAN, prints one JSON object and exits. It never reads a
// location, opens no network connection and writes no file.
//
//   HomeAuditWiFi            print what can be read now (waits 3s at most)
//   HomeAuditWiFi --scan     also list every BSSID advertising the same SSID
//   HomeAuditWiFi --prompt   wait up to 2 minutes for the permission dialog
import AppKit
import CoreLocation
import CoreWLAN

let args = Set(CommandLine.arguments.dropFirst())
let waitSeconds: TimeInterval = args.contains("--prompt") ? 120 : 3

final class Helper: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    var finished = false

    func applicationDidFinishLaunching(_ note: Notification) {
        manager.delegate = self
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
        if manager.authorizationStatus != .notDetermined {
            finish()
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + waitSeconds) { self.finish() }
    }

    func locationManagerDidChangeAuthorization(_ m: CLLocationManager) {
        if m.authorizationStatus != .notDetermined { finish() }
    }

    func finish() {
        if finished { return }
        finished = true

        let status = manager.authorizationStatus
        let statusName: String
        switch status {
        case .notDetermined: statusName = "not_determined"
        case .restricted:    statusName = "restricted"
        case .denied:        statusName = "denied"
        default:             statusName = "authorized"
        }

        var out: [String: Any] = [
            "helper": 1,
            "location_services_on": CLLocationManager.locationServicesEnabled(),
            "authorization": statusName,
        ]
        let iface = CWWiFiClient.shared().interface()
        out["interface"] = iface?.interfaceName ?? NSNull()
        let ssid = iface?.ssid()
        out["ssid"] = ssid ?? NSNull()
        out["bssid"] = iface?.bssid() ?? NSNull()

        if args.contains("--scan"), let iface = iface, let ssid = ssid {
            do {
                let found = try iface.scanForNetworks(withName: nil)
                let same = found.filter { $0.ssid == ssid }.compactMap { $0.bssid }
                out["same_ssid_bssids"] = Array(Set(same)).sorted()
                out["networks_seen"] = found.count
            } catch {
                out["scan_error"] = error.localizedDescription
            }
        }

        if let data = try? JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            print(text)
        }
        exit(0)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let helper = Helper()
app.delegate = helper
app.run()
