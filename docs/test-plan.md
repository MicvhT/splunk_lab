# SIEM Lab Test Plan

**Purpose:**  
Repeatable, versioned tests to verify end-to-end ingestion, parsing/normalization, dashboards, and alerts for the lab (pfSense → Ubuntu Splunk UF → Splunk indexer).

- **Author:** Micah Thompson 
- **Date:** 2025-11-06  
- **Version:** 0.1  
- **Related docs:** `architecture.md`, `configs/forwarder/inputs.conf.example`, `configs/forwarder/outputs.conf.example`, `dashboards/siem_lab_overview.xml`

---

## 1. Overview & Objectives
- Verify logs flow end-to-end from test generator (Kali) → pfSense → Ubuntu forwarder → Splunk indexer.  
- Confirm `sourcetype` assignment (e.g. `linux_secure`) and field extraction for `src_ip`, `dst_ip`, `dst_port`, `action`.  
- Validate dashboard panels and saved-search alerts (recon, port scans, SSH brute force).  
- Provide reproducible steps, expected outcomes, and troubleshooting commands.

---

### TC1 — Network Reachability (Kali → Ubuntu)

**Objective:**  
Verify basic network reachability from Kali to the Ubuntu target (the host running the UF / Splunk or the SIEM target). This proves VMs are on the expected internal networks and common ports respond as expected.

**Preconditions**
- `ENV` block in this doc populated (`KALI_IP`, `UBUNTU_IP`, `INDEXER_IP`, etc.).
- VMs powered on and connected to the correct VirtualBox internal networks (e.g., `LabNet`, `SiemNet`).
- pfSense rules allow traffic between Kali and Ubuntu (or pfSense not in the path for the chosen internal network).
- Terminal open on Kali (attacker) and a terminal open on Ubuntu (target/indexer).

**Steps**
1. From **Kali**: confirm IP and interfaces.
```bash
hostname && ip -br addr > evidence/tc1-kali-ip-$(date +%Y%m%dT%H%M%S).log
cat evidence/tc1-kali-ip-*.log
```

2. From **Ubuntu**: confirm IP and interfaces. 
```bash
hostname && ip -br addr > evidence/tc1-ubuntu-ip-$(date +%Y%m%dT%H%M%S).log
cat evidence/tc1-ubuntu-ip-*.log
```

3. From **Kali**: test TCP connectivity to common target ports (no DNS lookups).
```bash
# run from Kali; saves stdout to evidence file
nc -vnz $UBUNTU_IP 22 80 443 2>&1 | tee evidence/tc1-nc-$(date +%Y%m%dT%H%M%S).log
```
**Interpretation**
- `succeeded` or `open` = reachable and port open
- `Connection refused` = host reachable but port closed (also acceptable to show reachability).
- `No route to host` / `Operation timed out` = network problem.

4. From **Kali**: quick ICMP check.
```bash
ping -c 4 $UBUNTU_IP | tee evidence/tc1-ping-$(date +%Y%m%dT%H%M%S).log
```

**Note**:ICMP may be blocked by host firewall/pfSense; ping failure ≠ always broken network.

5. Optional deeper network probe (run from **Kali**):
```bash
# light SYN scan (safe, local lab)
sudo nmap -sS -Pn --top-ports 50 $UBUNTU_IP -oN evidence/tc1-nmap-$(date +%Y%m%dT%H%M%S).log
```

6. Optional decisive capture (run on Indexer/Ubuntu to see packets):
```bash
# on indexer/Ubuntu
sudo tcpdump -n -i any host $KALI_IP and host $UBUNTU_IP -c 40 -vv > evidence/tc1-tcpdump-$(date +%Y%m%dT%H%M%S).log
# while it runs, re-run the nc/ping commands on Kali (steps 3 & 4)
```

### TC1 - Expected Results
- `ip -br addr` on Kali shows `KALI_IP` and on Ubuntu shows `UBUNTU_IP`
- `nc -vnz` produces `succeeded` or `Connection refused` for reachable host (not `No route to host` or `Operation timed out`).
- `ping` receives replies if ICMP is allowed; if ICMP is blocked, `nc`/`tcpdump` to prove connectivity.
- if tcpdump is run on indexer, you should see packets from `KALI_IP` to `UBUNTU_IP`

### TC1 - Evidence To Collect
- `evidence/tc1-kali-ip-<timestamp>.log`
- `evidence/tc1-ubuntu-ip-<timestamp>.log`
- `evidence/tc1-nc-<timestamp>.log`
- `evidence/tc1-ping-<timestamp>.log`
- Optional: `evidence/tc1-nmap-<timestamp>.log`
- Optional decisive capture: `evidence/tc1-tcpdump-<timestamp>.log`

**Owner:** You ,  **PRIORITY:** High

### TC1 - Pass/Fail Criteria
- **PASS** if `nc` shows `succeeded` or `Connection refused` (proves reachability) OR tcpdump shows packets from `KALI_IP` to `UBUNTU_IP`.
- **FAIL** if `nc`/tcpdump shows no packets and `No route to host`/`Operation timed out` persists. 

### Networking/Troubleshooting
- If `No route to host` or no tcpdump lines:
    - Check VirtualBox network mode for each VM (Machine → Settings → Network). Make sure both Kali and pfSense/Ubuntu adapters are on the same named Internal Network (e.g., `LabNet` / `SiemNet`) where applicable. 
    - Verify pfSense interface assignments and firewall rules (LAN/SIEMOPT1) if pfSense is in the path.
    - On Kali/Ubuntu, inspect `ip route` to ensure default gateway points to pfSense where intended.
    - Re-run `ip -br addr` on both VMs and confirm the IPs used in commands match actual interface IPs.

---

### TC2 — SSH auth failure generation (host logs → Splunk)

**Objective:**  
Generate failed SSH login attempts from Kali to the Ubuntu host and verify the failures are: 
1. written to `/var/log/auth.log` on the host 
2. monitored by the Universal Forwarder 
3. indexed in Splunk with `sourcetype=linux_secure` (index = `$INDEX_UBUNTU`).

**Preconditions**
- ENV block is populated (`KALI_IP`, `UBUNTU_IP`, `INDEXER_IP`, `INDEX_HOSTS`, `UF_PORT`).
- Universal Forwarder installed and running on Ubuntu, configured to monitor `/var/log/auth.log` and forward to `INDEXER_IP:UF_PORT`.
- Splunk indexer receiving data and time picker set to the test window (e.g., Last 15 minutes).
- SSH server running on Ubuntu (sshd). If SSH is disabled, use `logger` fallback commands below.

**Steps**
1. (Optional) Confirm sshd is running on Ubuntu:
```bash
# on Ubuntu
sudo systemctl status sshd --no-pager
```

2. On **Kali** - generate multiple failed SSH login attempts (fast loop):
```bash
# run on Kali to produce failed attempts referencing the target IP and save the output
# on Kali
for i in {1..8}; do ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no invaliduser@$UBUNTU_IP || true; sleep 1; done 2>&1 | tee evidence/tc2-kali-ssh-attempts-$(date +%Y%m%dT%H%M%S).log
```

If SSH is blocked/unavailable on the host, use `logger` to create an auth-like message on the Ubuntu host (run this on Ubuntu, simulates a local syslog message):
```bash
# on Ubuntu (simulate an auth failure)
logger -p auth.warning "FAILED LOGIN TEST invaliduser from $KALI_IP"
# save it
sudo tail -n 40 /var/log/auth.log | tee evidence/tc2-authlog-simulated-$(date +%Y%m%dT%H%M%S).log
```

3. On **Ubuntu**: verify host log recorded the attempts and save evidence:
```bash
# check and save last matching lines
sudo grep "$KALI_IP" /var/log/auth.log | tail -n 200 | tee evidence/tc2-authlog-$(date +%Y%m%dT%H%M%S).log
# also show last 100 lines for context
sudo tail -n 100 /var/log/auth.log | tee evidence/tc2-authlog-last100-$(date +%Y%m%dT%H%M%S).log
```

4. On **Ubuntu (forwarder host)**: confirm the UF monitors the file and is connected:
```bash
# show effective monitor stanzas
sudo /opt/splunkforwarder/bin/splunk btool inputs list --debug | egrep -A4 '/var/log/auth.log|monitor:///var/log/auth.log' | tee evidence/tc2-btool-inputs-$(date +%Y%m%dT%H%M%S).log

# list forward-server(s)
sudo /opt/splunkforwarder/bin/splunk list forward-server | tee evidence/tc2-forward-server-$(date +%Y%m%dT%H%M%S).log

# tail forwarder log for send/connect errors
sudo tail -n 200 /opt/splunkforwarder/var/log/splunk/splunkd.log | egrep -i 'connect|retry|tcpout|error|queue' | tee evidence/tc2-uf-log-$(date +%Y%m%dT%H%M%S).log
```

5. In **Splunk Web (Search)**: run these searches (time picker = Last 15 minutes) and save a sample `_raw` event:
```bash
# 1) Very broad: any event with the Kali IP
index=* "$KALI_IP" | table _time index host sourcetype _raw | sort -_time | head 50

# 2) Auth-specific: find failed passwords and extract src_ip
index=$INDEX_HOSTS sourcetype=linux_secure "Failed password" OR "Invalid user" earliest=-15m
| rex "(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| search src_ip="$KALI_IP"
| table _time host sourcetype src_ip _raw
| sort -_time
```
- Save one `_raw` event to a text file (copy/paste event body) and store as:
`evidence/tc2-splunk-event-$(date +%Y%m%dT%H%M%S).txt`

6. (Optional) If nothing appears in Splunk but host logs exist, run a decisive packet trace on the indexer while repeating the Kali SSH loop to prove network reachability:
```bash
# on indexer
sudo tcpdump -n -i any host $KALI_IP and host $INDEXER_IP -c 40 -vv | tee evidence/tc2-tcpdump-$(date +%Y%m%dT%H%M%S).log
```

### TC2 - Expected Results
- Ubuntu `/var/log/auth.log` contains multiple `Failed password` `or Invalid user lines` that mention `$KALI_IP`.
- UF `btool` output shows a `monitor:///var/log/auth.log` stanza with `sourcetype = linux_secure` (or the sourcetype you expect) and `index = $INDEX_UBUNTU`.
- Splunk search (index = $INDEX_UBUNTU, sourcetype = linux_secure) returns at least one event containing $KALI_IP within 60 seconds of generation.

### TC2 - Evidence To Collect
- `evidence/tc2-kali-ssh-attempts-YYYYMMDDTHHMMSS.log` (Kali terminal output)
- `evidence/tc2-authlog-YYYYMMDDTHHMMSS.log` (Ubuntu grep of auth.log)
- `evidence/tc2-btool-inputs-YYYYMMDDTHHMMSS.log` (UF btool output)
- `evidence/tc2-forward-server-YYYYMMDDTHHMMSS.log` (UF forward-server output)
- `evidence/tc2-uf-log-YYYYMMDDTHHMMSS.log` (UF splunkd.log tail)
- `evidence/tc2-splunk-event-YYYYMMDDTHHMMSS.txt` (one sample Splunk _raw event)
- Optional: `evidence/tc2-tcpdump-YYYYMMDDTHHMMSS.log` or `.pcap`

**Owner:** You ,  **PRIORITY:** High

### TC2 - Pass/Fail Criteria
- **PASS** if: `host /var/log/auth.log` shows `Failed password` events from `$KALI_IP` AND Splunk returns at least one event in `index=$INDEX_HOSTS` with `sourcetype=linux_secure` referencing `$KALI_IP` within 60 seconds.
- **FAIL** if: host log contains events but Splunk returns no events and UF btool shows monitor + forward-server is Active — then UF/Indexer ingestion issue to troubleshoot. If host log does not contain events, network/ssh reachability problem — go back to TC1.

### Troubleshooting
- If **no host lines** on Ubuntu:
```bash
# on Ubuntu
sudo tail -n 200 /var/log/auth.log
sudo ss -ltnp | egrep '22|sshd' || true
sudo systemctl status sshd
# re-run SSH attempt from Kali and watch auth.log live
sudo tail -f /var/log/auth.log
```
- If **UF Forwarder disconnected**: recreate/update /opt/splunkforwarder/etc/system/local/outputs.conf with:
```bash
[tcpout]
defaultGroup = indexers

[tcpout:indexers]
server = $INDEXER_IP:$UF_PORT
```
then restart UF:
```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

---

### TC3 — Packet Capture On Indexer (decisive network proof)

**Objective:**  
Confirm packets from the attacker (Kali) reach the indexer/Ubuntu (Splunk) and verify whether they are sent to the expected listener ports (UF TCP 9997, pfSense syslog 1514), by capturing packets on the indexer and analyzing them.

**Preconditions**
- `ENV` block populated (`KALI_IP`, `INDEXER_IP`, `UBUNTU_IP`, `UF_PORT`, `SYSLOG_PORT`).
- You have sudo on the indexer/Ubuntu machine to run tcpdump.
- Enough disk space to store a small pcap file in `siem_lab/evidence/`.

**High-level approach**
1. Start a short tcpdump on the indexer capturing traffic between Kali and the indexer.
2. On Kali, run the test traffic (SSH attempts, nc, nmap, syslog test).
3. Stop tcpdump and analyze the pcap for connections to `INDEXER_IP:$UF_PORT` and `INDEXER_IP:$SYSLOG_PORT`.
4. Save human-readable extracts and the raw pcap as evidence.

---

**Steps**
1. Start decisive capture on the indexer (Ubuntu where Splunk runs)
```bash
# create evidence dir if not exists
mkdir -p ~/siem_lab/evidence

# capture only traffic between KALI_IP and INDEXER_IP, write to pcap (raw)
sudo tcpdump -n -i any host $KALI_IP and host $INDEXER_IP -w ~/siem_lab/evidence/tc3-traffic-$KALI_IP-to-$INDEXER_IP-$(date +%Y%m%dT%H%M%S).pcap -c 200
# -n: numeric IPs (no DNS), -i any: all interfaces, -w: write pcap, -c: stop after 200 packets
```
- Keep the terminal running; tcpdump will exit after `-c` packets or Ctrl+C.
- If you expect a lot of traffic, increase -c or omit and stop with Ctrl+C.

2. While tcpdump is running: generate test traffic from Kali
Run these from Kali (copy output to evidence on Kali as well):
```bash
# 1) SSH failed attempts (auth failures used in TC2)
for i in {1..8}; do ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no invaliduser@$UBUNTU_IP || true; sleep 1; done

# 2) Netcat checks to UF and web ports
nc -vnz $INDEXER_IP $UF_PORT 2>&1 | tee ~/siem_lab/evidence/tc3-nc-uf-$(date +%Y%m%dT%H%M%S).log
nc -vnz $INDEXER_IP 22 80 443 2>&1 | tee ~/siem_lab/evidence/tc3-nc-ports-$(date +%Y%m%dT%H%M%S).log

# 3) If you want syslog test (pfSense->Splunk style), send a UDP syslog
echo "<134>1 $(date -Iseconds) TEST pfSense->Splunk: test from $KALI_IP" | nc -u $INDEXER_IP $SYSLOG_PORT
```

3. Stop capture (if you used Ctrl+C or waited for -c to finish)

4. Produce readable extracts (on indexer)
```bash
PCAP=~/siem_lab/evidence/tc3-traffic-$KALI_IP-to-$INDEXER_IP-*.pcap

# A) quick summary with tcpdump (text)
sudo tcpdump -n -r $PCAP -vv | tee ~/siem_lab/evidence/tc3-tcpdump-readable-$(date +%Y%m%dT%H%M%S).log

# B) filter only traffic to UF_PORT or SYSLOG_PORT (text)
sudo tcpdump -n -r $PCAP -vv "(tcp and dst port $UF_PORT) or (udp and dst port $SYSLOG_PORT) or (tcp and src port $UF_PORT) or (udp and src port $SYSLOG_PORT)" | tee ~/siem_lab/evidence/tc3-uf-syslog-only-$(date +%Y%m%dT%H%M%S).log

# C) optionally convert pcap to json/text via tshark (if available)
sudo tshark -r $PCAP -T pdml > ~/siem_lab/evidence/tc3-pdml-$(date +%Y%m%dT%H%M%S).xml 2>/dev/null || true
```

5. Check Splunk internal for incoming connections at the same time. In Splunk Web (Search) or CLI:
```bash
# in Splunk Search (time matching capture window)
index=_internal (TcpInput OR tcpin OR "Incoming connection" OR tcpout) | tail 50
```
Or on indexer shell:
```bash
# show listening sockets
sudo ss -ltnp | egrep "$UF_PORT|$SYSLOG_PORT|8000|8089" || true

# tail Splunk logs for tcp input messages
sudo tail -n 200 /opt/splunk/var/log/splunk/splunkd.log | egrep -i 'TcpInput|tcpin|incoming connection|listening|reject|error' -n | tee ~/siem_lab/evidence/tc3-splunkd-internal-$(date +%Y%m%dT%H%M%S).log
```

### TC3 - Evidence To Collect
- Raw pcap: siem_lab/evidence/`tc3-traffic-<kali>-to-<indexer>-YYYYMMDDTHHMMSS.pcap`
- Human-readable extracts: `siem_lab/evidence/tc3-tcpdump-readable-<timestamp>.log` and `tc3-uf-syslog-only-<timestamp>.log`
- Kali-side evidence of generated traffic: `siem_lab/evidence/tc3-nc-uf-...log, tc3-nmap-...log`
- Splunk/internal evidence: `siem_lab/evidence/tc3-splunkd-internal-<timestamp>.log`

**Owner:** You ,  **PRIORITY:** High

### TC3 - Pass/Fail Criteria
- **PASS** if tcpdump shows packets from `KALI_IP` to `INDEXER_IP` destined for the expected port(s) (TCP 9997 for UF or UDP/TCP 1514 for syslog) AND Splunk shows corresponding activity (events or TCP input messages in `_internal`) within the same time window.
- **FAIL** if tcpdump shows no packets at all between KALI and INDEXER, or packets are visible but not reaching intended port (e.g., RSTs/no listener), or Splunk listener returns errors in logs.

### Troubleshooting
1. Confirm `KALI_IP` is correct on the Kali VM: `ip -br addr` and use the same IP in capture and tests.
2. On indexer, run `sudo ss -ltnp` to ensure Splunk or UF is listening on `UF_PORT`.
3. Confirm capture interface — `sudo tcpdump -D` lists interfaces; use the correct one or `-i any`.
4. If capture shows packets arriving but Splunk not receiving, check `sudo tail -n 200 /opt/splunk/var/log/splunk/splunkd.log` for `TcpInput` / connection messages.
5. If capture shows no packets, check VirtualBox network settings and pfSense firewall rules; run `tcpdump` on the Kali host too to verify it sent them.
6. If UDP syslog packets arrive at the indexer/host’s network stack on the port you configured but Splunk not parsing, ensure Splunk has a UDP input configured for that port (Settings → Data inputs → UDP).

---

### TC4 — Universal Forwarder (UF) connectivity & inputs verification

**Objective:**  
Verify the Splunk Universal Forwarder on the Ubuntu host is correctly configured to monitor `/var/log/auth.log` (and other host files), is connected to the indexer (`INDEXER_IP:UF_PORT`), and is successfully forwarding events.

**Preconditions**
- `ENV` block populated (`UBUNTU_IP`, `INDEXER_IP`, `UF_PORT`, `INDEX_UBUNTU`).
- UF installed under `/opt/splunkforwarder/` and you have `sudo` on the forwarder.
- Indexer reachable from forwarder (see TC1/TC3).

---

**Steps (run on the forwarder first)**
1. Check UF service / binary availability
```bash
# check splunk UF binary exists & show status
sudo /opt/splunkforwarder/bin/splunk status 2>/dev/null || echo "splunk forwarder binary not found"
# if installed as a systemd service (some installs), also:
sudo systemctl status splunkd --no-pager || true
```
- Expected: splunkd shown as running, or /opt/splunkforwarder/bin/splunk responds (prints status).

2. Confirm/verify forward-server target(s):
```bash 
sudo /opt/splunkforwarder/bin/splunk list forward-server 2>&1 | tee ~/siem_lab/evidence/tc4-forward-server-$(date +%Y%m%dT%H%M%S).log
```
- Expected: line like:
```bash
$INDEXER_IP:$UF_PORT (Active)
```
- If it shows `Disconnected` or nothing, UF is not connected.

3. Show effected monitored inputs (use btool)
```bash
sudo /opt/splunkforwarder/bin/splunk btool inputs list --debug | egrep -A6 '/var/log/auth.log|monitor:///var/log/auth.log' | tee ~/siem_lab/evidence/tc4-btool-inputs-$(date +%Y%m%dT%H%M%S).log
```
- Expected: a stanza similar to:
```bash
[monitor:///var/log/auth.log]
index = ubuntu
sourcetype = linux_secure
disabled = false
```
- If `sourcetype` or `index` are missing, the forwarder will send raw source without the expected metadata.

4. Check forwarder logs for connection / send errors:
```bash
sudo tail -n 300 /opt/splunkforwarder/var/log/splunk/splunkd.log | egrep -i 'connect|retry|tcpout|error|tcpout-server|forwarder' -n | tee ~/siem_lab/evidence/tc4-uf-log-$(date +%Y%m%dT%H%M%S).log
```
- What to look for: repeated `Retry` messages, `tcpout` errors, or `Unable to connect to` indicate network/auth issues. Successful connect lines mention `Established connection to` or `TcpOutputProc` messages.

5. Test TCP reachability from UF to indexer (quick network test)
```bash
# use nc to test TCP to the indexer port (9997)
nc -vz $INDEXER_IP $UF_PORT 2>&1 | tee ~/siem_lab/evidence/tc4-nc-$(date +%Y%m%dT%H%M%S).log
```

6. **(OPTIONAL)** Force-forward a small test event
- Use `logger` on the forwarder to generate a local syslog event that should be monitored by the UF (only if `/var/log/syslog` or `/var/log/auth.log` is being watched):
```bash
logger -t SIEM_TEST "SIEM_TEST_EVENT from $HOSTNAME at $(date -Iseconds)" && echo "logger sent" | tee ~/siem_lab/evidence/tc4-logger-sent-$(date +%Y%m%dT%H%M%S).log
# saves to file
# then wait ~10-30s and check UF logs and Splunk Search
```

7. Cross-checks (run on the indexer / Splunk host)
```bash
# on indexer
sudo ss -ltnp | egrep "$UF_PORT|8000|8089" || true
# or
sudo netstat -tulpen 2>/dev/null | egrep "$UF_PORT|splunk" || true
```
- Expected: splunkd listening on TCP `9997` (or whatever UF_PORT you configured). 

8. Check indexer internal logs for inbound forwarder connections in Splunk Web (Search) or via CLI:
```bash
# In Splunk Web (Search), set time window to last 15m:
index=_internal component=TcpInput OR tcpin OR "incoming" | sort - _time | head 50

# OR on indexer shell (tail splunkd.log)
sudo tail -n 200 /opt/splunk/var/log/splunk/splunkd.log | egrep -i 'TcpInput|tcpin|incoming connection|forwarder' -n | tee ~/siem_lab/evidence/tc4-indexer-splunkd-$(date +%Y%m%dT%H%M%S).log
```
- Expected: messages showing an incoming connection from the forwarder IP (UBUNTU_IP) to the indexer.

9. Search for test events or recent forwarder events
In Splunk Web (Search & Reporting), time range = Last 15 minutes, run:
```bash
# quick check for forwarder host in any index
host="$UBUNTU_HOSTNAME" OR host="$UBUNTU_IP" | stats count by index, sourcetype | sort - count

# specifically check expected index and sourcetype
index=$INDEX_HOSTS sourcetype=linux:auth $UBUNTU_IP | table _time host sourcetype _raw | sort -_time | head 20
```

### TC4 - Evidence To Collect
- `siem_lab/evidence/tc4-forward-server-YYYYMMDDTHHMMSS.log` (output of splunk list forward-server)
- `siem_lab/evidence/tc4-btool-inputs-YYYYMMDDTHHMMSS.log` (btool inputs)
- `siem_lab/evidence/tc4-uf-log-YYYYMMDDTHHMMSS.log` (tail of UF splunkd.log)
- `siem_lab/evidence/tc4-nc-YYYYMMDDTHHMMSS.log` (nc reachability test)
- `siem_lab/evidence/tc4-logger-sent-YYYYMMDDTHHMMSS.log` (if used)
- `siem_lab/evidence/tc4-indexer-splunkd-YYYYMMDDTHHMMSS.log` (indexer splunkd tail)

**Owner:** You ,  **PRIORITY:** High


### TC4 - Pass/Fail 
**PASS** if:
    - `splunk list forward-server` shows `INDEXER_IP:UF_PORT (Active)` for the forwarder, AND
    - `btool inputs` shows `monitor:///var/log/auth.log` with `sourcetype = linux_secure` (or configured value), AND
    - Splunk indexer shows incoming connection logs (`TcpInput`) and at least one event from the forwarder host appears in `index=$INDEX_UBUNTU` within 60 seconds of test generation.

**FAIL** if:
    - `splunk list forward-server` shows `Disconnected`/no server, OR
    - `btool inputs` does not include the expected monitor stanza, OR
    - UF logs show persistent `Retry` or `Unable to connect` errors, OR
    - No events appear in Splunk despite host logs containing the test event.

### Troubleshooting
- If forward-server not set or disconnected
```bash
# on forwarder: set outputs.conf (replace INDEXER_IP and UF_PORT)
sudo tee /opt/splunkforwarder/etc/system/local/outputs.conf > /dev/null <<'EOF'
[tcpout]
defaultGroup = indexers

[tcpout:indexers]
server = $INDEXER_IP:$UF_PORT

[tcpout-server://$INDEXER_IP:$UF_PORT]
disabled = false
EOF

# set ownership & restart
sudo chown -R splunk:splunk /opt/splunkforwarder/etc/system/local
sudo /opt/splunkforwarder/bin/splunk restart
```
- If inputs missing or wrong sourcetype
```bash
sudo tee /opt/splunkforwarder/etc/system/local/inputs.conf > /dev/null <<'EOF'
[monitor:///var/log/auth.log]
sourcetype = linux:auth
index = $INDEX_HOSTS
disabled = false
EOF
sudo chown -R splunk:splunk /opt/splunkforwarder/etc/system/local
sudo /opt/splunkforwarder/bin/splunk restart
```
- If UF logs show permission errors — ensure correct ownership:
```bash
sudo chown -R splunk:splunk /opt/splunkforwarder
```
- If firewall blocks outgoing TCP to indexer, adjust firewall rules in pfSense or through command line. 

---

### TC5 — Search & sourcetype verification in Splunk

**Objective:**  
Confirm events from the Ubuntu forwarder (host) are indexed, discover the *actual* `sourcetype`(s) assigned, and update/author queries and dashboard panels so they reliably surface the host events (SSH auth failures, host logs).

**Preconditions**
- ENV block populated (`KALI_IP`, `UBUNTU_IP`, `INDEX_UBUNTU`, etc.).
- You have Splunk Web access and permission to run searches, save events, and edit dashboards/saved searches.
- You have generated test events (TC2) and/or completed network proof (TC3).

---

**Steps**
1. Set time picker to the test window
- In Splunk Web Search, set the time range to `Last 15 minutes` (or the period you ran tests).

2. Find which sourcetypes exist for the host or IP (fast)
- By **host**:
```bash
index=* host="$UBUNTU_HOSTNAME" | stats count by index, sourcetype | sort - count
```
- By **IP**:
```bash
index=* "$KALI_IP" | stats count by index, sourcetype | sort - count
```

3. If you only know the index (search broadly)
```bash
index=$INDEX_HOSTS | stats count by sourcetype | sort - count
```
- Record the top 3 sourcetypes you see. These are the values to use (or normalize) in dashboards/searches.

4. Find sample events and save one _raw event to evidence
- Broad search to find an auth failure event:
```bash
index=$INDEX_UBUNTU ("Failed password" OR "Invalid user" OR "authentication failure" OR "SIEM_TEST_EVENT") | head 20
```
- Click a representative event → View → Raw. Copy the `_raw` text and save to a file locally:
```bash
evidence/tc5-sample-raw-YYYYMMDDTHHMMSS.txt
```
- Also note the `sourcetype` value shown in the event's metadata.

5. Extract fields from the sample _raw (ad-hoc rex)
- Use rex to extract the source IP and user (example handles common auth formats):
```bash
index=$INDEX_HOSTS ("Failed password" OR "Invalid user") earliest=-15m
| rex field=_raw "(?i)(?:from|rhost|SRC)[=:\s]*(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex field=_raw "(?i)(?:for|user|invalid user)[=:\s]*(?<user>[\w\-\.\@]+)"
| table _time host sourcetype src_ip user _raw
| sort - _time
```
- Adjust the second rex if your _raw uses different phrasing for user names

6. If sourcetypes vary, create a reusable macro (Search time normalization)
- In Splunk Web: Settings → Advanced search → Search macros → New macro:
    - Name: lab_auth_sourcetypes
    - Definition:
    ```bash
    (sourcetype=linux:auth OR sourcetype=auth OR sourcetype=syslog OR source="/var/log/auth.log")
    ```
    - **Use**: Can now call with backticks: `lab_auth_sourcetypes`
- Example using macro:
```bash
`lab_auth_sourcetypes` "Failed password"
| rex "(?i)(?:from|rhost)[=:\s]*(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by src_ip
```

7. Change dashboard panels to be flexible (one-off)
    - Replace sourcetype=linux:auth with the macro or a flexible clause:
    ```bash
    index=$INDEX_UBUNTU (sourcetype=linux_secure OR sourcetype=linux:auth OR sourcetype=auth OR "Failed password")
    | rex "(?i)(?:from|rhost)[=:\s]*(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    | stats count as failed_attempts by src_ip
    | where failed_attempts > 0
    ```

8. If you can change forwarder inputs (preferred long-term)
    - On the UF, ensure /opt/splunkforwarder/etc/system/local/inputs.conf has:
    ```bash
    [monitor:///var/log/auth.log]
    sourcetype = linux:auth
    index = ubuntu
    disabled = false
    ```
- Restart the forwarder to make future events consistent.

9. Verify fields are extracted for dashboard use
    - Run a search that produces the fields your panels expect:
    ```bash
    `lab_auth_sourcetypes` "Failed password" earliest=-15m
    | rex "(?i)(?:from|rhost)[=:\s]*(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    | rex "(?i)(?:for|user|invalid user)[=:\s]*(?<user>[\w\-\.\@]+)"
    | stats count as attempts by src_ip, user | sort - attempts
    ```
    - If `src_ip` or `user` are empty, tweak the `rex` using the sample `_raw` event saved earlier.

### TC5 - Expected Results
- You can list the actual `sourcetype`(s) producing host/auth events (via `stats count by sourcetype`).
- You have saved a sample `_raw` event to `evidence/tc5-sample-raw-YYYYMMDDTHHMMSS.txt`.
- A flexible SPL (macro or OR clause) returns the test events and extracts `src_ip` and `user` correctly for the dashboard panel.

### TC5 - Evidence To Collect
- `evidence/tc5-sourcetype-list-YYYYMMDDTHHMMSS.txt` (copy/paste results of `stats count by sourcetype`)
- `evidence/tc5-sample-raw-YYYYMMDDTHHMMSS.txt` (one full _raw event)
- `evidence/tc5-rex-test-YYYYMMDDTHHMMSS.log` (output of the rex search that shows extracted fields)
- Screenshot(s) of dashboard panel(s) after the query is updated: `evidence/tc5-panel-YYYYMMDDTHHMMSS.png`

**Owner:** You ,  **PRIORITY:** High

### TC5 - Pass/Fail Criteria
-**PASS** if: you identify the actual sourcetype(s) and you can run a dashboard/search query (macro or flexible SPL) that returns the test events and extracts `src_ip` (and `user`) reliably within the test window.
- **FAIL** if: no events are returned by flexible searches, sample `_raw` cannot be found for the test timeframe, or field extractions fail repeatedly even after tuning `rex`.

### Troubleshooting
- Verify time picker covers the test time. 
- Run a very borad search to ensure events exist:
```bash
index=$INDEX_HOSTS "$KALI_IP" | head 50
```
- Use the saved `_raw` event to craft exact rex patterns (copy/paste pieces from `_raw` into the regex).
- When in doubt, set the UF to explicitly set sourcetype = `linux_secure` at the forwarder (preferred) so searches don’t need extra complexity.

---
### TC6 — pfSense syslog ingestion (optional)

**Objective:**
Verify pfSense firewall logs (syslog) are forwarded to Splunk and ingested into `index=pfsense` with fields like `src_ip`, `dst_port`, `action`, and `rule` available for dashboards. 


**Preconditions**
- `ENV` block populated (`INDEXER_IP`, `SYSLOG_PORT`, `INDEX_PFSENSE`).
- Splunk indexer reachable from pfSense (network validated by TC1/TC3).
- You have Splunk admin access to create a UDP/TCP input and view indexes.
- You can access the pfSense GUI (or SSH/shell) to configure remote syslog.

## Design notes / recommendation
- **Preferred for lab:** Use **TCP syslog** (e.g., 1514 TCP) for reliability. If you must use UDP, it’s okay for tests but packets can be lost.
- Configure Splunk to listen on the chosen port and index the incoming messages to `INDEX_PFSENSE` with an appropriate `sourcetype` (e.g., `pfsense:syslog`).

**Steps**

### A — Configure Splunk to receive syslog (indexer)
1.  In Splunk Web: **Settings → Data inputs → UDP** (or **TCP**) → **New**.  
   - Port: `$SYSLOG_PORT` (e.g., `1514`)  
   - Source type: `pfsense:syslog` (or `syslog`)  
   - Host: `IP` or `DNS` (choose `IP` to use incoming IP as host)  
   - Index: `INDEX_PFSENSE`  
   - Save.

2. Alternatively, add `inputs.conf` on the indexer (app/local):
```bash
# /opt/splunk/etc/apps/TA-local/local/inputs.conf
[udp://1514]
sourcetype = pfsense:syslog
index = pfsense
connection_host = ip
disabled = false

# OR for TCP:
[tcp://1514]
sourcetype = pfsense:syslog
index = pfsense
connection_host = ip
disabled = false
```
- Restart Splunk if you add conf files:
```bash
sudo /opt/splunk/bin/splunk restart
```

### B — Configure pfSense to forward logs
- (Using pfSense GUI)
1. Log into pfSense GUI → Status → System Logs → Settings (or check your pfSense version: Remote syslog configuration is under Status > System Logs > Settings).
2. Add a remote syslog server:
    - Remote Syslog Servers (or "Remote Syslog Servers" table): add `INDEXER_IP` and port `SYSLOG_PORT` (specify protocol if UI exposes TCP/UDP).
    - For format, prefer `BSD`/`syslog` default. Set facility/priority defaults as desired.
- Save and apply.

### C — Send a test syslog message
- Use Diagnostics → Command Prompt on pfSense and run:
```bash
# sends a local syslog message that will be forwarded
logger -p daemon.info "PFTEST: test syslog from pfSense $(date -Iseconds) SRC=$KALI_IP DST=$UBUNTU_IP DPT=22"
```

### D — Confirm packets arrive at the indexer (OS-level)
- Run this one indexer while test messgage is sent:
```bash
sudo tcpdump -n -i any "host $PFSENSE_IP and udp port $SYSLOG_PORT" -c 5 -vv
# or for TCP:
sudo tcpdump -n -i any "host $PFSENSE_IP and port $SYSLOG_PORT" -c 5 -vv
```
- Or filter by destination port:
```bash
sudo tcpdump -n -i any "port $SYSLOG_PORT" -c 10 -vv
```

### E — Confirm Splunk ingested the event
- In Splunk Search (time range = Last 15 minutes):
```bash
index=$INDEX_PFSENSE "PFTEST" OR "pfsense TEST" | table _time host sourcetype index _raw | sort -_time | head 50
```
- If nothing  appears, broaden the search:
```bash
index=* "pfsense TEST" OR "PFTEST" | stats count by index,sourcetype,host | sort - count
```

### TC6 - Expected Results
`tcpdump` shows the test packet(s) arriving at `INDEXER_IP:$SYSLOG_PORT`.
- Splunk quickly (within 60 seconds) indexes the test event in `index=INDEX_PFSENSE` with the chosen `sourcetype` (e.g., `pfsense:syslog`).
- `_raw` contains the test string and you can extract `SRC`, `DST`, `DPT` with `rex` or props/transforms.

### TC6 - Evidence To Collect
- `siem_lab/evidence/tc6-pfsense-config-YYYYMMDDTHHMMSS.png` (screenshot of pfSense Remote Syslog settings)
- `siem_lab/evidence/tc6-syslog-send-YYYYMMDDTHHMMSS.log` (output of test send command)
- `siem_lab/evidence/tc6-tcpdump-YYYYMMDDTHHMMSS.log` (tcpdump readable extract)
- `siem_lab/evidence/tc6-splunk-event-YYYYMMDDTHHMMSS.txt` (sample `_raw` event saved from Splunk)
- `siem_lab/evidence/tc6-splunk-inputs-YYYYMMDDTHHMMSS.log`(screenshot or `inputs.conf` showing udp/tcp stanza)

**Owner:** You ,  **PRIORITY:** Medium

### TC6 - Pass/Fail Criteria
- **PASS** if: `tcpdump` shows syslog packets arriving at `INDEXER_IP:$SYSLOG_PORT` AND Splunk returns at least one event in `index=$INDEX_PFSENSE` containing the test text within 60s.
- **FAIL** if: OS-level capture shows no packets (network/pfSense problem), or packets arrive but Splunk is not listening / not indexing (no event in `index=$INDEX_PFSENSE`).

### Troubleshooting

---
### TC7 — Dashboard validation

---
### TC8 — Alert test (saved search)

---

### Environment / Variables

```bash
KALI_IP=<KALI_VM_IP>
KALI_HOSTNAME=<KALI_VM_HOSTNAME>
UBUNTU_HOSTNAME=<UBUNTU_VM_HOSTNAME>
UBUNTU_IP=<UBUNTU_VM_IP>    # forwarder host / Splunk host
INDEXER_IP=<INDEXER_VM_IP>   # Splunk indexer IP
INDEX_PFSENSE=<PFSENSE_INDEX>
INDEX_UBUNTU=<UBUNTU_INDEX>      # index where host logs land
UF_PORT=<UF_PORT>               # UF -> Indexer port
SYSLOG_PORT=<SYSLOG_PORT>           # pfSense -> Splunk syslog port
TIME_WINDOW='Last 15 minutes'
```