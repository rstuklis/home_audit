// HomeAuditWiFi — the audit's hands on the Wi-Fi interface.
//
// macOS withholds the SSID and every BSSID from a process without Location
// Services access, and Terminal never asks for that access, so it cannot be
// added to the list by hand. An app that asks for itself can be. This is that
// app. It never reads a location, opens no network connection of its own and
// writes no file.
//
//   HomeAuditWiFi                    print what can be read now (waits 3s at most)
//   HomeAuditWiFi --scan             also list every BSSID advertising the same SSID
//   HomeAuditWiFi --prompt           wait up to 2 minutes for the permission dialog
//   HomeAuditWiFi --setup SSID...    window to type each network's Wi-Fi password
//   HomeAuditWiFi --status SSID...   which of those have a stored password (yes/no only)
//   HomeAuditWiFi --join SSID        join that network using its stored password
//
// Why the passwords live here. Auditing several home networks means moving the
// Mac between them, and macOS will not join even a saved network from a script
// without being handed the password ("Error: -3900 tmpErr"). `networksetup`
// takes it only as an argument, where `ps` shows it to every process on the
// machine. So this app keeps them instead: typed into a secure field, written
// straight to the login Keychain, read back only by --join and passed to
// CoreWLAN in memory. A password is never printed, logged, put on a command
// line, or returned to the caller — not by any mode.
import AppKit
import CoreLocation
import CoreWLAN
import Security

let keychainService = "homenetaudit-wifi"

// MARK: - Keychain

func keychainQuery(_ ssid: String) -> [String: Any] {
    return [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: ssid]
}

/// Whether an item exists. Asks for attributes only, so it never unlocks the secret.
func keychainHas(_ ssid: String) -> Bool {
    var q = keychainQuery(ssid)
    q[kSecReturnAttributes as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
}

func keychainRead(_ ssid: String) -> String? {
    var q = keychainQuery(ssid)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var out: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
          let data = out as? Data else { return nil }
    return String(data: data, encoding: .utf8)
}

func keychainWrite(_ ssid: String, _ password: String) -> OSStatus {
    let data = Data(password.utf8)
    let update = SecItemUpdate(keychainQuery(ssid) as CFDictionary,
                               [kSecValueData as String: data] as CFDictionary)
    if update != errSecItemNotFound { return update }
    var add = keychainQuery(ssid)
    add[kSecValueData as String] = data
    add[kSecAttrLabel as String] = "Home Audit Wi-Fi: \(ssid)"
    add[kSecAttrDescription as String] = "Wi-Fi password used by the home network audit to join this network"
    return SecItemAdd(add as CFDictionary, nil)
}

// MARK: - Arguments

func validSSID(_ s: String) -> Bool {
    let n = s.utf8.count
    return n >= 1 && n <= 32 && !s.hasPrefix("--") && s.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
}

/// WPA/WPA2/WPA3-Personal: 8 to 63 characters, or exactly 64 hex digits.
func validPassphrase(_ p: String) -> Bool {
    let n = p.utf8.count
    if n == 64 { return p.allSatisfy { $0.isHexDigit } }
    return n >= 8 && n <= 63
}

func emit(_ object: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
       let text = String(data: data, encoding: .utf8) {
        print(text)
    }
}

let argv = Array(CommandLine.arguments.dropFirst())
let flags = Set(argv.filter { $0.hasPrefix("--") })
let names = argv.filter { !$0.hasPrefix("--") }
let known: Set<String> = ["--scan", "--prompt", "--setup", "--status", "--join"]

if let bad = flags.first(where: { !known.contains($0) }) {
    emit(["helper": 1, "error": "unknown option \(bad)"]); exit(64)
}
if let bad = names.first(where: { !validSSID($0) }) {
    emit(["helper": 1, "error": "not a valid network name: \(bad.prefix(40))"]); exit(64)
}

// --status needs no permission and no app: answer and leave.
if flags.contains("--status") {
    var stored: [String: Bool] = [:]
    for n in names { stored[n] = keychainHas(n) }
    emit(["helper": 1, "stored": stored]); exit(0)
}

// MARK: - The setup window

final class SetupWindow: NSObject, NSWindowDelegate {
    let ssids: [String]
    var fields: [NSSecureTextField] = []
    var window: NSWindow!

    init(ssids: [String]) { self.ssids = ssids }

    func show() {
        let grid = NSGridView(numberOfColumns: 3, rows: 0)
        grid.columnSpacing = 12
        grid.rowSpacing = 10
        for ssid in ssids {
            let name = NSTextField(labelWithString: ssid)
            name.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
            let field = NSSecureTextField()
            field.placeholderString = "Wi-Fi password"
            field.widthAnchor.constraint(equalToConstant: 260).isActive = true
            let state = NSTextField(labelWithString: keychainHas(ssid) ? "already stored" : "not stored yet")
            state.textColor = .secondaryLabelColor
            fields.append(field)
            grid.addRow(with: [name, field, state])
        }

        let intro = NSTextField(wrappingLabelWithString:
            "Type the Wi-Fi password for each network. They are saved to your login Keychain and used only by this app, to move this Mac between your own networks during an audit. They are never shown, logged or sent anywhere.\n\nLeave a box empty to keep what is already stored.")
        intro.preferredMaxLayoutWidth = 470

        let save = NSButton(title: "Save to Keychain", target: self, action: #selector(savePressed))
        save.keyEquivalent = "\r"
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelPressed))
        cancel.keyEquivalent = "\u{1b}"
        let buttons = NSStackView(views: [cancel, save])
        buttons.orientation = .horizontal

        let stack = NSStackView(views: [intro, grid, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        buttons.trailingAnchor.constraint(equalTo: stack.trailingAnchor, constant: -20).isActive = true

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 300),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Home Audit Wi-Fi — network passwords"
        window.contentView = stack
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        if let first = fields.first { window.makeFirstResponder(first) }
        NSApp.activate(ignoringOtherApps: true)
    }

    func alert(_ title: String, _ text: String, style: NSAlert.Style = .warning) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = text
        a.alertStyle = style
        a.beginSheetModal(for: window, completionHandler: nil)
    }

    @objc func savePressed() {
        var toSave: [(String, String)] = []
        for (ssid, field) in zip(ssids, fields) {
            let value = field.stringValue
            if value.isEmpty { continue }
            guard validPassphrase(value) else {
                alert("That does not look like a Wi-Fi password",
                      "The password for \(ssid) must be 8 to 63 characters long. Nothing has been saved.")
                return
            }
            toSave.append((ssid, value))
        }
        guard !toSave.isEmpty else {
            alert("Nothing to save", "Every box is empty. Type at least one password, or press Cancel.")
            return
        }
        var failed: [String] = []
        for (ssid, value) in toSave where keychainWrite(ssid, value) != errSecSuccess {
            failed.append(ssid)
        }
        for field in fields { field.stringValue = "" }
        if !failed.isEmpty {
            alert("Could not save everything", "The Keychain refused: \(failed.joined(separator: ", ")).")
            return
        }
        finish(saved: toSave.map { $0.0 })
    }

    @objc func cancelPressed() { finish(saved: []) }
    func windowWillClose(_ notification: Notification) { finish(saved: []) }

    var done = false
    func finish(saved: [String]) {
        if done { return }
        done = true
        var stored: [String: Bool] = [:]
        for s in ssids { stored[s] = keychainHas(s) }
        emit(["helper": 1, "setup": saved.isEmpty ? "cancelled" : "saved",
              "saved": saved.sorted(), "stored": stored])
        exit(0)
    }
}

// MARK: - Reading and joining

final class Helper: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    var finished = false
    var setup: SetupWindow?

    func applicationDidFinishLaunching(_ note: Notification) {
        if flags.contains("--setup") {
            guard !names.isEmpty else { emit(["helper": 1, "error": "--setup needs network names"]); exit(64) }
            NSApp.setActivationPolicy(.regular)
            setup = SetupWindow(ssids: names)
            setup?.show()
            return
        }
        manager.delegate = self
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
        if manager.authorizationStatus != .notDetermined {
            finish()
            return
        }
        let wait: TimeInterval = flags.contains("--prompt") ? 120 : 3
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { self.finish() }
    }

    func locationManagerDidChangeAuthorization(_ m: CLLocationManager) {
        if flags.contains("--setup") { return }
        if m.authorizationStatus != .notDetermined { finish() }
    }

    func join(_ ssid: String, on iface: CWInterface) -> [String: Any] {
        if iface.ssid() == ssid { return ["joined": true, "already": true] }
        guard let password = keychainRead(ssid) else {
            return ["joined": false, "join_error": "no stored password for this network — run --setup"]
        }
        do {
            let found = try iface.scanForNetworks(withName: ssid).filter { $0.ssid == ssid }
            guard let best = found.max(by: { $0.rssiValue < $1.rssiValue }) else {
                return ["joined": false, "join_error": "network not in range"]
            }
            try iface.associate(to: best, password: password)
        } catch {
            return ["joined": false, "join_error": error.localizedDescription]
        }
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if iface.ssid() == ssid { return ["joined": true] }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return ["joined": false, "join_error": "associated, but the interface never reported the network"]
    }

    func finish() {
        if finished { return }
        finished = true

        let statusName: String
        switch manager.authorizationStatus {
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

        if flags.contains("--join") {
            if names.count == 1, let iface = iface {
                for (k, v) in join(names[0], on: iface) { out[k] = v }
            } else {
                out["joined"] = false
                out["join_error"] = names.count == 1 ? "no Wi-Fi interface" : "--join takes exactly one network name"
            }
        }

        let ssid = iface?.ssid()
        out["ssid"] = ssid ?? NSNull()
        out["bssid"] = iface?.bssid() ?? NSNull()

        if flags.contains("--scan"), let iface = iface, let ssid = ssid {
            do {
                let found = try iface.scanForNetworks(withName: nil)
                let same = found.filter { $0.ssid == ssid }.compactMap { $0.bssid }
                out["same_ssid_bssids"] = Array(Set(same)).sorted()
                out["networks_seen"] = found.count
            } catch {
                out["scan_error"] = error.localizedDescription
            }
        }

        emit(out)
        exit((flags.contains("--join") && (out["joined"] as? Bool) != true) ? 1 : 0)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let helper = Helper()
app.delegate = helper
app.run()
