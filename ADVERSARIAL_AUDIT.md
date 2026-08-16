Verified all 46 surviving entries against the source at `/Users/rstuklis/src/home_audit/home_net_audit.py` (5774 lines). Merged 12 duplicate pairs/quads, dropped 0 outright, demoted 6, corrected 3 line numbers.

# Adversarial audit — final report
`home_net_audit.py` @ `1d07da1` · 62 candidates → 46 survived skeptics → **34 findings after merge**

Ranked by the threat model: *(a) the tool asserting "safe" when it is not, (b) LAN-attacker-controlled input.*

---

## Tier 1 — HIGH: a LAN attacker or local tamperer forces a false all-clear

### H1. `arp -a` is run without `-n`, so an attacker-chosen reverse-DNS name becomes the neighbour's MAC
**`home_net_audit.py:417,421`**
`_read_arp_bsd` runs `run(["arp","-a"])` (name resolution on) and then `re.search` for a MAC-shaped token over the **whole line** — the resolved hostname is column 1, so it wins over the real `at <mac>` column.
```python
417:    out = run(["arp", "-a"])
420:    ip_m  = re.search(r"\(([\d.]+)\)", line)
421:    mac_m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
```
Reproduced: `'aa:bb:cc:dd:ee:ff.local (192.168.1.1) at de:ad:be:ef:00:01 …'` → `{'192.168.1.1': 'aa:bb:cc:dd:ee:ff'}`.
**Scenario:** attacker ARP-poisons the gateway and publishes a PTR/mDNS name equal to the router's genuine MAC. `monitor_snapshot`'s `gateway_mac` (`:1654`) pins to the pre-poison value forever → the HIGH `gateway_mac_changed` (`:1677`) never fires; `check_arp_spoofing` prints `[OK] MAC address stable`. A forged name containing `(a.b.c.d)` also refiles a row under another IP, hiding a new device from `diff_baseline`.
**Fix:** `arp -an`, and anchor: `re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)`, MAC from group 2 only.

### H2. `parse_dhcp_options` hunts for the magic cookie instead of using the fixed offset
**`home_net_audit.py:3349`** — `magic = data.find(b"\x63\x82\x53\x63")`, `i = magic + 4`.
RFC 2131 fixes the cookie at byte 236. `sname` (44) and `file` (108) are sender-controlled free-form bytes; a decoy cookie there plus a `0xff` terminator makes the parser stop before the real options.
**Scenario:** rogue DHCP puts `option 3 = 192.168.1.1` in `file`, and `option 3 = attacker` + `option 121 = 0.0.0.0/0 via attacker` at 236. Verified: `describe_dhcp_offer(pkt)` → `router:['192.168.1.1'], static_routes:[]`; `pkt[236:]` → the real poison. `diff_dhcp_offer` emits nothing.
**Fix:** `if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63": return {}` then `i = 240`.

### H3. UPnP trusts the first SSDP responder; source address is discarded
**`home_net_audit.py:3580,3584`**
```python
3580:  data, _ = sock.recvfrom(4096)      # peer address thrown away
3584:  location = loc_m.group(1).strip(); break   # first answer wins
```
`gateway` is used only as a fallback base URL (`:3610`) that never fires when a LOCATION arrived. `MX: 2` means a conforming router delays its reply; an attacker answers instantly.
**Scenario:** attacker at .50 answers, serves a description pointing at itself, returns `SpecifiedArrayIndexInvalid` → report prints "The gateway reported no active UPnP port mappings" while the router forwards a port to the attacker. `EVIDENCE["upnp"]` (`:2274`) then labels the fabrication *"the gateway's own list."* Same primitive fetches any `location` via `urlopen` (`:3603`, default opener honours `file:`/`ftp:`) and aims 100 SOAP POSTs at any host via an absolute `<controlURL>` (`:3619`).
**Fix:** keep `addr` from `recvfrom`, ignore datagrams not from `gateway`; require `location`/`ctrl_url` scheme in `http(s)` with hostname == `gateway`.

### H4. A legacy-shaped baseline short-circuits before the chain is read
**`home_net_audit.py:1313`** (`read_history()` is not reached until `:1340`)
```python
1313:  if not isinstance(record, dict) or record.get("format") != BASELINE_FORMAT:
1314:      return {"status": "legacy", "keyed": False, …}
```
`describe_baseline_integrity` maps `legacy` → REVIEW (`:2087`); `load_baseline` returns the bare dict verbatim (`:1294`).
**Scenario:** after 5 keyed saves, `json.dump(forged_state, open(baseline.json,'w'))` — no `format` key, or `"format": "2"` as a string. Result: `[REVIEW] Baseline predates integrity checking` + `No changes since baseline.`, while `history.jsonl` still holds 5 keyed entries. Strictly cheaper than the two attacks the suite already defends (`tests/test_baseline_integrity.py:131,151`) — no history write, no seal forgery.
**Fix:** read history first; a non-format-2 record with a non-empty chain is a **downgrade**, return `modified` (HIGH). Genuine legacy has no history file.

### H5. A deleted or corrupt baseline reports "No baseline saved yet" at INFO
**`home_net_audit.py:1274,1311`** — `load_baseline_record` folds `FileNotFoundError | JSONDecodeError | OSError` into `None`; `verify_baseline` returns `absent` (INFO, `:2086`) before consulting the chain.
The module has the mirror status (`chain_missing`, HIGH) but nothing for record-missing-while-chain-present.
**Scenario:** `echo '{' > ~/.home_net_audit/baseline.json` after 5 sealed runs → `[INFO] No baseline saved yet.`, no comparison, then `main`'s unconditional `save_baseline` (`:5762`) writes seq 6 chained to run 5. Every later run reports `[OK] Seal verified`. Self-healing for the attacker. The design note at `:1364` scopes the accepted gap to removing the *whole* directory — this is not that case.
**Fix:** `if record is None and read_history(): return {"status":"record_missing", … HIGH}`, naming the last recorded seq. Separate `JSONDecodeError`/`OSError` from `FileNotFoundError`.

### H6. Change detection never compares the gateway, its MAC, or the ARP result
**`home_net_audit.py:2660-2862`** (`diff_baseline`)
`state["gateway"]` (`:5283`) and `state["arp_spoof"]` (`:5367`) are sealed into the baseline; `diff_baseline` compares only devices, `router_open_ports`, `upstream_open_ports`, `wifi_bssids`, DHCP offer, `router_tls.sha256`, `ipv6_routers`, `dns`. Grep confirms no `gateway`/`macs_seen` comparison anywhere in the function. Meanwhile `check_arp_spoofing`'s verdict is `len(macs_seen) > 1` over 5 polls / ~6 s (`:3740`) — a steady-state poisoner yields one MAC and prints `[OK] MAC address stable`.
**Scenario:** Day 1 baseline `gateway_mac = router`. Day 2 a continuous poisoner is in-path. Audit prints `[OK] MAC address stable across all polls: <attacker>` and `No changes since baseline.` Verified: `diff_baseline(old, new)` with a changed gateway IP and changed `macs_seen` returns `[]`. The monitor has the check (`:1671,1677`); the audit does not.
**Fix:** in `diff_baseline`, add guarded comparisons of `gateway` and `arp_spoof.macs_seen` (HIGH when both sides non-empty and differ); pass the baseline MAC into `check_arp_spoofing` so *stable-but-different* is a finding.

### H7. The HTML report silently omits six check families, including three HIGH-capable ones
**`home_net_audit.py:4593-4830`** — 15 `if "<key>" in state` sections; grep of the function body for `evil_twin|ipv6|interception|trust_store|router_tls|upstream_open_ports|dsl` → **zero hits**. `action_full_audit` populates all of them (`:5295,5298,5312,5369,5372,5376`).
`probe_dns_interception` (`:962`), `check_trust_store` (`:928`), `check_evil_twin` (`:3236`), `check_ipv6_routers` (`:631`) all return `risk:"HIGH"`.
**Scenario:** rogue RA + intercepted port 53. Terminal prints both HIGHs. Rendered report contains **zero** occurrences of "intercept"/"IPv6", the DNS section lists the configured resolvers unqualified, and the provenance footer (`:4842`, via `findings_by_evidence` `:2306`) still counts them: *"The other N finding(s) rest on … measurements this tool made itself."* `dsl` even emits a provenance row for a section that does not exist. `tests/test_html_report.py:692` pins the 15 headings, baking the omission in.
**Fix:** drive the section list from a table keyed by state key; render `risk_badge(r["risk"])` + `_esc(r["note"])` for each missing key, and fail loudly on any state key carrying a `risk` the renderer does not know.

### H8. A truncated credential sweep is reported as "every one was refused"
**`home_net_audit.py:4096` + `:4041`** (merged: lockout-drop and coverage-verdict)
`probe_default_credentials` returns `(successes, lockout_note, coverage)`; `action_default_creds` prints `[STOPPED]` (`:4084`) but returns `{"gateway", "successes", "coverage"}` — **`lockout_note` never crosses the boundary**. The terminal suppresses the coverage line via `elif not lockout_note:` (`:4093`); the HTML path (`:4761`) calls `credential_coverage_verdict(dc.get("coverage"))` unconditionally, whose first live branch is:
```python
4041:  if attempts:
4043:      return "OK", f"{attempts} credential pair(s) submitted on port(s) {where} and every one was refused."
```
`coverage` has no completion flag. Second path to the same lie: `attempts` is incremented **before** the request (`:3904,:3954`), and `_fetch`'s bare `except Exception: return None, ""` (`:3886`) turns a router silently dropping connections into a counted "attempt" that was never refused.
**Scenario:** router 429s or blocks after N failures. HTML shows a green `OK — 8 credential pair(s) submitted on port(s) 80 and every one was refused`; the sealed baseline records the same forever. No mention that the sweep aborted, that the admin account may be locked, or that most of `DEFAULT_CREDS` was never tried.
**Fix:** set `coverage["aborted"] = lockout_note` inside `probe_default_credentials`; increment `attempts` only on a non-`None` response and count `(None,"")` separately; make `credential_coverage_verdict` return REVIEW with the abort text **before** the `if attempts:` branch.

### H9. `_publish_https` reports success for a redirect that discarded the POST body, and forwards the sink token
**`home_net_audit.py:1516-1519`**
```python
1516:  req = urllib.request.Request(url, data=canonical_json(payload), headers=headers)
1517:  with urllib.request.urlopen(req, timeout=10) as r: code = r.getcode()
1519:  return {"published": True, … f"Receipt accepted by {url} (HTTP {code})."}
```
No custom opener → CPython's `HTTPRedirectHandler` converts POST→bodiless GET on 301/302/303 and copies every header except content-length/type, so `Authorization: Bearer <sink token>` goes to the redirect target. The scheme test (`:1483`) accepts plain `http://` despite `--publish-to` advertising `https://`.
**Scenario:** (a) `http://collector/receipts` 301s to https (near-universal) → every receipt silently dropped, tool says "Receipt accepted (HTTP 200)", sink stays empty, a wiped local baseline becomes undetectable. (b) On-path LAN attacker 302s to their own host and collects the append-only sink token. Same function is the transport for heartbeats (`:1835`) and alerts (`:1924`), so a swallowed HIGH alert prints nothing at all (callers branch on `published`).
**Fix:** build an opener whose redirect handler refuses redirects; require the final URL to equal the configured URL; reject non-`https` destinations for token-bearing requests.

### H10. Every receipt/heartbeat publish failure is discarded
**`home_net_audit.py:1262`, `:2009`**
`publish_receipt`'s contract (`:1468`): *"The caller is expected to surface `published` — a receipt that silently failed to leave the machine is the same as never having sent one."* `record["_receipt"] = publish_receipt(record)` is the **only** occurrence of `_receipt` in the file; both `save_baseline` callers (`:5213`, `:5762`) discard the return. `run_monitor` calls `monitor_heartbeat(...)` bare at `:2009` and advances `last_heartbeat` regardless — while the sibling `send_alert` two lines up *does* surface `published` (`:2001-2002`).
**Scenario:** `HOME_NET_AUDIT_SINK=/Volumes/attic/receipts` unmounted, or an expired `SINK_TOKEN`. Startup warning only fires when the sink is *unset* (`:1957`). Months of runs publish nothing, print nothing, and the monitor heartbeats into the void. Combined with H9/M1 the next comparison then reports `[OK] Local baseline agrees with N off-host receipt(s)`.
**Fix:** print `record["_receipt"]["detail"]` when `published` is false in both save paths; mirror the `send_alert` pattern at `:2009` and only advance `last_heartbeat` on success.

### H11. One poll that cannot read the gateway MAC overwrites the reference with `None`
**`home_net_audit.py:2004,2006`**
`monitor_snapshot` never pings (`:1654`, unlike `check_arp_spoofing`), so an incomplete/aged-out ARP entry yields `gateway_mac=None`. `diff_snapshots` correctly skips (`if old_mac and new_mac …`, `:1678`) — but `previous = snapshot` / `save_monitor_state(snapshot, polled_at)` run unconditionally, persisting the null.
**Scenario (reproduced):** good → `None` → attacker. Poll 2 skipped (new is None), poll 3 skipped (old is None). Output is a single `REVIEW neighbour_appeared`; the HIGH `gateway_mac_changed` never fires, then or ever, and the attacker MAC is written to `monitor_state.json` as the new normal. An attacker can force the blank poll (flood so `arp -a` exceeds `run()`'s 10 s timeout → `read_arp_table()` → `{}`).
**Fix:** ping the gateway in `monitor_snapshot`; carry forward the last non-null value before storing: `snapshot["gateway_mac"] = snapshot["gateway_mac"] or previous.get("gateway_mac")`, and emit REVIEW when it becomes unresolvable.

### H12. Heartbeats are published under a different chain id than the audit reads back
**`home_net_audit.py:1818` (publish) vs `:1846` (read)**
`chain_id()` = `sha256(basename(BASELINE_FILE))[:12]` (`:1396`). `main` dispatches `--monitor` at `:5707` and returns — `use_current_network_baseline` is only called at `:5208,:5225,:5286`, all audit paths. So heartbeats carry `sha256("baseline.json")`; the readers (`:5236`, `:5413`) run *after* selection repointed `BASELINE_FILE` to `baseline-<key>.json`.
**Scenario (reproduced):** chain before selection `aca6b74e85f7`, after `select_network_baseline("192.168.1.0/24")` `9fba15685e94`; `read_heartbeats(sink)` → `[]` → `observation_gaps([])` → `[]` → `describe_observation_gaps` returns `None` — **the same value it returns for "observation was continuous."** A monitor dead for two weeks prints nothing. This is the exact failure the feature exists to remove, and it is dead in every per-network deployment.
**Fix:** call `use_current_network_baseline()` at the top of `run_monitor`, before the loop. Belt-and-braces: report heartbeats with an unknown chain rather than dropping them.

### H13. A failed alert is never retried, never spooled, and the change is adopted as the new normal
**`home_net_audit.py:2000-2006`**
`send_alert` returns `{published: False}`; the loop prints `(not delivered: …)` to stdout **on the host under suspicion** and falls through to `previous = snapshot` / `save_monitor_state(...)`. No queue, no retry, no local spool (`grep spool|retry|undeliver|pending` → nothing).
**Scenario (reproduced):** with `_publish_path` raising `OSError` during the poisoning, `run_monitor` returns `gateway_mac_changed` but `alerts.jsonl` is never created; restore the sink and two further polls yield `[]`. The adversary the alert describes is in-path by definition and can drop the alert POST while letting heartbeats through, so no coverage gap is reported either.
**Fix:** persist undelivered events (`undelivered` list in `monitor_state.json`) and re-attempt on every poll until `published`; keep re-raising while undelivered.

---

## Tier 2 — MEDIUM

### M1. `compare_with_receipts` returns `ok` when the local seq is *ahead* of every receipt
**`:1628`** — after `if local_seq < highest` (`:1614`), `match = [r … == local_seq]` is empty, both guards skip, fall through to `{"status":"ok","detail": f"Local baseline agrees with {len(receipts)} off-host receipt(s)."}`. Verified: `({'seq':99,'seal':'FORGED'}, [7 receipts])` → `[OK]`. A seq higher than anything receipted means the run was never published — the strongest available signal that the local record is fabricated. Also fires benignly whenever publishing failed (H10), asserting agreement about runs the receipts never saw.
**Fix:** branch on `local_seq > highest` → REVIEW `unpublished_runs`, naming the count.

### M2. `seal_mismatch` compares against the *newest* receipt for a seq
**`:1621-1622`** — `match[-1]` is the last line in file order, i.e. the one an append-only sink lets the host add. `({'seq':7,'seal':'FORGED'}, [{7,'real'},{7,'FORGED'}])` → `ok`. `tests/test_receipts.py:82` passes only because it publishes one receipt per seq.
**Fix:** compare against `match[0]`, and flag `len({r["seal"] for r in match}) > 1` as tampering outright.

### M3. An `https://` sink is write-only: `read_receipts` opens the URL as a filesystem path
**`:1523-1539`** — `open(source)` → `FileNotFoundError` (an `OSError`) → `return []`. There is no HTTP GET of receipts anywhere in the file. Publishing branches on scheme (`:1483`); reading does not.
**Scenario:** 30 published runs, attacker deletes `~/.home_net_audit`. Next run prints `[REVIEW] No off-host receipts to compare against.` — false, and REVIEW instead of HIGH `history_truncated`. `--publish-to`'s own help advertises the URL with the guarantee that fails.
**Fix:** implement an HTTP GET path, or report a distinct "sink is write-only from here; the truncation check cannot run" status — never reuse `no_receipts`.

### M4. `send_alert` sends the receipt sink's bearer token to the alert host
**`:1924`** — `_publish_https(payload, destination, token or os.environ.get(SINK_TOKEN_ENV), "alert")`. `resolve_alert_sink` (`:1903`) is a deliberately *different* endpoint (`tests/test_monitor.py:160`), and there is no alert-specific token env anywhere. `_publish_https` attaches `Authorization` to any URL with no host check.
**Scenario:** `HOME_NET_AUDIT_ALERT=https://hooks.slack.com/…` → every alert logs the append-only collector token at a third party.
**Fix:** dedicated `ALERT_TOKEN_ENV`, or the explicit `token` argument only.

### M5. Attacker-controlled KDF parameters crash or hang `verify_baseline`
**`:1327-1332`** — the `try` covers only `bytes.fromhex` and catches only `ValueError`; `derive_baseline_key` is outside it. Reproduced against a tampered baseline: `"salt":123` → `TypeError`; `"iterations":"200000"` → `TypeError`; `"iterations":0` → `ValueError`; `"kdf":[1,2]` → `AttributeError`; `"iterations":10**12` → hangs. No handler anywhere up the stack (call sites `:5229`, `:5406`; `main` and `__main__` are bare).
**Scenario:** the run dies with a traceback at the CHANGE DETECTION banner — before the diff, `save_baseline` and the HTML report — exactly where it would have printed `[HIGH] … altered since it was written.` The obvious user response (delete `~/.home_net_audit`) is the attacker's goal. `tests/test_baseline_integrity.py:126` asserts the opposite contract but only exercises `salt="not-hex"`.
**Fix:** validate `isinstance(kdf, dict)`, `isinstance(salt, str)`, `isinstance(iterations, int) and 1 <= iterations <= 10_000_000`; widen the `try` over `derive_baseline_key` and catch `(TypeError, ValueError, OverflowError)`.

### M6. A non-object JSON line in the receipt log crashes `compare_with_receipts`
**`:1584`** — `[r for r in receipts if r.get("kind") != "heartbeat" …]` with no `isinstance` guard, while the two sibling consumers of the same log do have one (`read_heartbeats` `:1845`, `code_attestations` `:2030`). `read_receipts` appends whatever `json.loads` returns.
**Scenario:** one line `null` in a shared sink → `AttributeError` at the CHANGE DETECTION section on every run: no verdict, no diff, no baseline saved, no report. Violates the module's own standard at `:1752` (*"a crash on a malformed line would turn the evidence trail into a denial of service"*).
**Fix:** filter non-dicts inside `read_receipts` so every consumer inherits the guard.

### M7. A non-object JSON line in `history.jsonl` crashes verification and saving
**`:1066`, `:1069`** — `entries.append(json.loads(line))` with only `JSONDecodeError` caught, and the outer handler is `FileNotFoundError` only (vs `OSError` in `read_receipts` `:1538`). A line `0` gives `verify_baseline` → `AttributeError` at `:1348` and `save_baseline` → `TypeError` at `:1236`. `tests/test_baseline_integrity.py:197` is named *"a corrupt history line does not crash verification"* but only exercises unparseable text.
**Fix:** `if isinstance(obj, dict): entries.append(obj)`; broaden to `except OSError: return []`.

### M8. `chain_id` is derived from the LAN-controlled subnet
**`:1579,1396`** — a renumbering rogue DHCP changes `BASELINE_FILE` → new chain digest → every existing receipt is dropped at `:1584` → `no_receipts` (REVIEW) instead of `history_truncated` (HIGH), plus `No baseline saved yet` and a fresh chain sealed at seq 1 under the attacker's key. `existing_key_for_same_network` (`:2437`) only rescues a changed prefix length, not a changed network address.
**Fix:** when the filtered list is empty but the raw log holds receipts for other chains, return a distinct `chain_unknown` status naming the count — never `no_receipts`.

### M9. The HTML ARP section badges green `OK` when zero MACs were resolved
**`:4712`** — `risk = "HIGH" if a.get("spoofing_suspected") else "OK"`, and `spoofing_suspected = len(macs_seen) > 1` (`:3740`) is False for both *stable* and *never observed*. The terminal gets this right (`:3754`, early return before the `[OK]` line). Worse: `action_arp_spoof_check` returns bare `{}` when the gateway is undeterminable (`:3749`) and callers store it unconditionally (`:5367`, `:5584`), so `"arp_spoof" in state` is true → green `OK` next to `Gateway: ?`. The same function already tri-states `router_open_ports` (`:4670`), `firewall` (`:4726`) and `default_creds` (`:4761`).
**Fix:** `risk = "HIGH" if suspected else ("OK" if a.get("macs_seen") else "REVIEW")` with body text saying nothing was compared.

### M10. A rogue-DHCP check that never ran renders as "No DHCP responses captured."
**`:4793,4801`** — `action_rogue_dhcp` returns `{"responders": [], "error": err}` (`:3530`) for the EACCES/EPERM and Local-Network-denial paths; the report reads only `responders` and never `error`. Grep: the literal `"error"` key has two producers (`:3530`, `:3677`) and **no consumer**. Binding port 68 needs root, so this is the default non-sudo outcome. `findings_by_evidence` still counts `dhcp` as MEASURED — *"which servers answered a DHCP request on the wire"* (`:2271`) — when no packet left the machine.
**Fix:** read `error` first and render `risk_badge("REVIEW")` + the text; exclude it from the MEASURED count.

### M11. `observation_gaps` hard-codes the 900 s cadence, so `--interval > 1800` reports a healthy monitor as down
**`:1867,1874`** — `threshold = max(interval*2, interval+60)` with `interval=HEARTBEAT_INTERVAL` because both readers (`:5236`, `:5413`) omit the argument. Real spacing is `max(interval, 900)`. The heartbeat payload records its own `"interval"` (`:1819`) and is never consulted.
**Scenario (reproduced):** `--interval 3600`, ten hourly heartbeats, monitor never down → `[REVIEW] Observation coverage: 9 window(s) with no monitoring, the longest 1h.` and, if the audit runs >30 min after the last beat, a `[HIGH] … the monitor is not running now` about a running monitor.
*(Correction to the original claim: the break-even is >1800 s, not >900 s.)*
**Fix:** derive the threshold from the heartbeats' own recorded interval.

### M12. `monitor_state.json` is one global file, and write failures are swallowed
**`:1736`, `:1800-1804`** (merged: cross-network reuse + unwritable state)
Single path for all networks — `select_network_baseline` repoints only `BASELINE_FILE`/`HISTORY_FILE` (`:2505`), and `run_monitor` never selects. `save_monitor_state` swallows `OSError` with a bare `pass` and returns nothing the caller inspects; `load_monitor_state` maps every failure to `(None, None)`, which `run_monitor` treats as a genuine first run (`:1969`).
**Scenario A (reproduced):** monitor at home, then café Wi-Fi → HIGH `gateway_changed`, HIGH `gateway_mac_changed` (*"while its IP stayed the same … ARP poisoning"* — factually false, the IP changed in the same batch), HIGH `dns_changed`, plus the mirror image on the way home. **Scenario B (reproduced):** state file unwritable/root-owned → every restart silently re-baselines into whatever it wakes up in, with no message; `run_monitor` returns `[]` across an 8-hour poisoning window. B is only partly covered off-host by the heartbeat gap report — which H12 shows is dead in real deployments.
**Fix:** key the state per network (`monitor_state-<key>.json`) and treat a foreign-network record as "no reference"; have `save_monitor_state` return success and `run_monitor` print HIGH when the reference cannot be persisted; distinguish absent from unreadable on load.

### M13. `parse_wifi_networks` drops any SSID ending in "Networks"/"Information" without clearing `ssid`
**`:3182`** — the reject branch `continue`s with `ssid` unchanged, so the rejected network's BSSIDs are attributed to the previous SSID.
**Scenario (a):** neighbour `AAA Guest Networks` listed first under `Other Local Wi-Fi Networks:` (itself swallowed) → its BSSID lands under the connected SSID → false `[HIGH] HomeNet is being advertised by aa:bb:… — an evil twin`, and that foreign BSSID is written into the baseline (`:5373`). **(b):** own SSID `Wong Networks` → all BSSIDs file under `en0`; `check_evil_twin` finds nothing for the real SSID → `[REVIEW] No BSSID visible … grant Location Services`, blaming permissions for a parser bug and blinding the check permanently.
**Fix:** exact-match the two headers; set `ssid = None` on rejection.

### M14. The credential probe sends up to 640 login attempts per port after announcing 16 pairs
**`:3953`** (`try_form_login`: 10 endpoints × 4 payloads, no break) × 16 `DEFAULT_CREDS` = 640 POSTs per port, ×4 open ports = 2560. The gate `if not has_form and get_code not in (200,)` (`:3950`) does not restrain a router that answers 200 for unknown paths. The `time.sleep(0.05)` calls (`:3995,:4002`) pace only the outer loop, so 40 POSTs per pair go back-to-back. `:4077` prints *"Testing 16 common credential pairs"* — the number the user consents to at the menu-14 prompt. Routers that lock silently (no 429, no lockout phrase) are not caught by `LockoutError` at all.
**Fix:** discover the working (endpoint, payload) shape once with a throwaway pair and submit only that for the remaining 15; sleep inside the payload loop; print the real worst-case count.

### M15. With `TPLINK_PASSWORD` set and no `--upstream`, the modem password goes to a hardcoded IP in cleartext
**`:5303`** — `tplink_ip = upstream_ip or "192.168.1.1"`, ignoring the `gateway` already in scope at `:5283`. `tplink_dsl_stats` builds `http://{ip}` and puts `Passwd=<base64(password)>` in the query string (`:3061-3064`); on failure it retries with `Passwd=<MD5>` (`:3071`) — a replayable authenticator. No on-link/identity check.
**Scenario:** LAN is 192.168.87.0/24; the GET goes off-link via the default route. Over a split-tunnel VPN or a router that forwards RFC1918 it reaches a stranger's device and lands in their access log. Failure prints only *"Could not retrieve DSL stats — auth failed."*
**Fix:** require `--upstream` (or fall back to `gateway`) and refuse an off-link/unspecified target; print the destination before transmitting.

### M16. `probe_dns_interception` validates nothing, in both directions
**`:952-966`** (merged)
(a) `sendto` and `recvfrom` share one `try` catching `(socket.timeout, OSError)` → a `sendto` that raised `ENETUNREACH`/`EACCES` (packet never left) returns `{"risk":"OK", "note":"…port 53 is not being transparently redirected."}` — a certification from zero observation. Every sibling probe keeps a third state (`probe_port` `:721`, `check_rogue_dhcp` `:3512`, SSDP `:3591`); this one does not.
(b) The socket is unconnected and the verdict at `:962` is emitted on the datagram merely existing — no check that `addr[0] == target`, `addr[1] == 53`, that `data` parses as DNS, or that the txid matches `qid=0x4a4a`. `data` is bound and never read. A stray or sprayed datagram on the ephemeral port produces a false `[HIGH]` naming an attacker-chosen responder.
**Fix:** `sock.connect((target, 53))`; separate the `sendto` failure into a REVIEW third state; require `len(data) >= 12` and a matching (randomised) txid before concluding interception.

### M17. `run()` decodes subprocess output as strict UTF-8
**`:194`** — `text=True` with no `errors=`, and `UnicodeDecodeError` (a `ValueError`) is not in the `except (TimeoutExpired, FileNotFoundError, OSError)` at `:198`. Reproduced: one 0xFF byte → uncaught.
**Scenario:** `arp -a` (`:417`, name resolution on) splices resolver-derived bytes into the output every poll. On macOS, mDNSResponder escapes only `.`, `\` and bytes ≤ 0x20 — high bytes pass through. A hostile PTR kills `--monitor` (loop catches only `KeyboardInterrupt`, `:2015`) or aborts a full audit at `action_wifi_security`, before firewall/sharing/listening/UPnP/DHCP/baseline-save. Every other untrusted decode in this file already uses `.decode("utf-8","ignore")`.
*(The SSID and `lsof` vectors from the original claim are not credible and should be struck.)*
**Fix:** `errors="replace"` in the one choke point.

### M18. The HTML report is written 0644 into a 0755 directory
**`:4890-4891`** — plain `os.makedirs` + `open(..., "w")`, no `_secure_dir()`, no chmod. The same data is protected at 0700/0600 elsewhere (`_secure_dir` `:1020`, `_write_json_atomic` mode `0o600`), and `_secure_dir` is only reachable from a baseline/history write. Verified with a fresh dir: `0o755` dir, `0o755 reports/`, `0o644` file.
**Scenario:** `--html-report --no-save-baseline` (or a first-run menu report) → the save block is skipped, nothing ever chmods the dir, and any local account reads MACs, SSID, topology, hostnames and accepted-credential usernames/ports/methods. (The password itself is correctly withheld, `:4752`.)
**Fix:** call `_secure_dir()` at the top of `generate_html_report`, create `reports/` with mode 0700, and write via `os.open(..., 0o600)`.

### M19. One future-dated heartbeat permanently disables the HIGH "the monitor is not running now"
**`:1874`** — `trailing = now - stamps[-1]` with no upper bound; a future stamp becomes `stamps[-1]`, `trailing` goes negative, no open gap is appended, and `risk = "HIGH" if open_gap else "REVIEW"` (`:1891`) degrades to a past-tense REVIEW. The sink is append-only by design, so the entry can never be removed. `_parse_stamp` (`:1749`) has no sanity bound, and its own docstring concedes the log is attacker-appendable. A wrong clock (VM resume, RTC-less Pi pre-NTP) produces it with no attacker.
**Scenario (reproduced):** beats at 00:00/00:15/00:30 plus `2099-01-01`, now +15 d → `[REVIEW] … the longest 26450d 23h` instead of `[HIGH] … the monitor is not running now`.
**Fix:** discard stamps later than `now` (small skew allowance) and report their presence as its own finding.

---

## Tier 3 — LOW

| # | file:line | Finding | Fix |
|---|---|---|---|
| L1 | `:3728` | `check_arp_spoofing` calls `subprocess.run(["ping","-c","1","-t","1",gateway])` with **no timeout and no try/except** — the only such call site in the file (`run()` `:194`, `ping()` `:790`, `launchctl` `:4355,:4402` all guard). A missing `ping` (Linux observer with iproute2 but not iputils) raises `FileNotFoundError` out of `action_full_audit` (`:5366`), skipping ~9 later checks, the baseline save and the report. | Route through `ping()`, or add `timeout=2` + `except (TimeoutExpired, OSError)`; use `-W 1` off macOS. |
| L2 | `:3677` vs `:4787` | `action_upnp_dump` returns `{"error": "No gateway"}` on the no-gateway path but `{"note": err}` everywhere else; the report reads only `note`, so a run that never sent an SSDP packet renders "No UPnP port mappings found." plus a provenance row crediting the gateway. | Use `note` in both; make the default text "UPnP was not queried". |
| L3 | `:4702-4703` | `_esc(w.get('auth','?'))` — the `'?'` default is dead because `check_wifi_security` always sets the key, so an unreadable mode renders `Auth: None`, which is the literal macOS string this same parser treats as an open network (`:3283`). Terminal uses `r['auth'] or 'unknown'` (`:3330`). Mitigated in-section by the adjacent REVIEW badge and note. | `_esc(w.get('auth') or 'unknown (could not be read)')`, same for `ssid`. |
| L4 | `:3494` | `sock.recvfrom(1024)` truncates a larger OFFER; options past byte 1024 are invisible to the poisoning check while the OS client applies them. Narrow: the DISCOVER omits option 57, so a compliant server never exceeds 576 B, and a malicious one can simply omit the options instead. | `recvfrom(4096)`. |
| L5 | `:2709,:2798` | `_split` excludes locally-administered MACs from `appeared`/`vanished`/`moved`; the only remaining signal is a count reported on a strict rise. An intruder setting the LAA bit is never *named*, and is fully silent if a household private MAC drops off the same run. Documented and tested tradeoff (`tests/test_diff_baseline.py::test_a_steady_household_is_silent`), and cloning a baseline MAC is a strictly quieter evasion — so this raises attacker cost by ~0. | Report private MACs unseen in the previous run as an INFO/REVIEW line; treat `(randomized/private MAC)` as a non-name so the device still counts as unlabelled. |
| L6 | `:5076,:821` | `resolve_subnets` bounds only parseability; `discover_devices` does `list(subnet.hosts())` + 50-worker `pool.map(ping, …)`. `--subnet 10.0.0.0/8` → 16.7M subprocesses. Self-inflicted via an explicit override, prints "Sweeping 10.0.0.0/8" first, interruptible — ergonomics, not a defect. | Warn/clamp above ~4096 addresses; ARP discovery cannot see past the on-link prefix anyway. |

---

## What was checked and found clean

- **`describe_code_attestation` on unfiltered receipts** — the missing chain filter at `:5242/:5419` is real but harmless: `chain` identifies a *network*, not a machine, so a shared sink does not produce a false "the script's digest changed". Reporting a digest change across all chains is the intended behaviour.
- **`state["dhcp"]` responder IP interpolated without `_esc` (`:4799`)** — the only bare interpolation in the report, but the value comes from `addr[0]` of a UDP socket, i.e. a kernel-formatted dotted quad; not attacker-controllable text. Documented as intentional.
- **`migrate_legacy_baseline` destination asymmetry (`:2544` vs `:2581`)** — reachable only when `BASELINE_DIR != dirname(BASELINE_FILE)`, a state no supported configuration produces.
- **Router-hostname `self_attested` badge** — the `None` branch is dead in production; `action_router_hostname` (`:4157`) never omits the field.
- **`_write_json_atomic` / `_secure_dir`** — correct: mkstemp + chmod 0600 + `os.replace`, dir forced to 0700, temp unlinked on failure. Baseline and history file modes are covered by `tests/test_baseline_integrity.py:293-302`.
- **`parse_neigh_iproute` (`:388`)** — anchored `re.match` keyed off `lladdr`; immune to the H1 defect. `ndp -n` call sites correctly pass `-n` with a comment explaining why.
- **`carry_forward_unmeasured` / `swept_anywhere` / `devices_measured`** — the unmeasured-vs-empty discipline is implemented correctly for ports, devices and scanned subnets. (`router_tls` is missing from `CARRY_FORWARD_KEYS` at `:1117`; see coverage gaps.)
- **`diff_snapshots` null-tolerance (`:1678`)** — correct in isolation; the defect is the unconditional adoption at `:2004` (H11).
- **Accepted credentials never written to the report file** (`:4750-4752`) — verified, including in the raw bytes.
- **`onoff()` (`:4615`), firewall REVIEW (`:4726`), `router_open_ports is None` REVIEW (`:4670`), `credential_coverage_verdict`'s no-login-page branch** — the tri-state discipline these commits introduced is correctly applied at those four sites. H7/H8/M9/M10 are the sites the sweep missed.

## Coverage gaps

1. **H1 exploit chain, last hop unproven.** DNS/mDNS labels permit `:` and macOS's mDNSResponder escapes only `.`, `\` and bytes ≤ 0x20, so a colon-bearing PTR *should* reach `arp(8)` verbatim — not demonstrated end-to-end without standing up a hostile resolver. The parse defect itself is unconditional and reproduces regardless. On glibc, `ns_name_ntop` escapes high bytes, which likely neutralises the Linux-observer variant of both H1 and M17.
2. **H9 redirect behaviour is stdlib-version-dependent.** Reproduced on the CPython 3.13 in this environment (`HTTPRedirectHandler.redirect_request` → bodiless GET, `Authorization` preserved cross-host). Not re-verified across other runtimes.
3. **M3 fix shape is unresolved.** DEPLOYMENT.md recommends a *write-only* collector token, so implementing an HTTP GET may be refused by the sink anyway; the correct remedy may be a distinct "not readable from here" status rather than a fetch. Needs a product decision.
4. **`router_tls` is absent from `CARRY_FORWARD_KEYS` (`:1117`).** A failed handshake writes `{"present": False, "sha256": None}` over a real fingerprint, and `diff_baseline` then skips the cert comparison (`if old_cert and new_cert`, `:2844`). Verified mechanically; skeptics split on severity because the loss self-heals after one successful run and the failing run prints `certificate present: False`. Carried as a **low-medium hardening item**, not a ranked finding: add `router_tls` to `CARRY_FORWARD_KEYS` and treat `sha256 is None` as unmeasured.
5. **M12 Scenario B severity depends on H12.** Whether an unwritable `monitor_state.json` is silent depends on whether the off-host heartbeat gap report works — which H12 shows it does not, in per-network deployments. Fix H12 first, then re-rate.
6. **Not audited:** the speed-test path (`:2877-2904`), `check_trust_store`'s `security dump-trust-settings` parsing, `lookup_vendor`'s network OUI fetch (`:860`), `tools/capture_fixtures.py` redaction correctness, and the `seal_baseline.py` helper.
7. **Not attempted:** any dynamic testing against real network hardware. All reproductions were against the module with stubbed `run`/sockets, or pure-function calls with hand-built inputs.