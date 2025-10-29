# SIEM Lab Test Plan

**Purpose:**  
Repeatable, versioned tests to verify end-to-end ingestion, parsing/normalization, dashboards, and alerts for the lab (pfSense → Ubuntu Splunk UF → Splunk indexer).

- **Author:** Micah Thompson 
- **Date:** 2025-10-29  
- **Version:** 0.1  
- **Related docs:** `architecture.md`, `configs/forwarder/inputs.conf.example`, `configs/forwarder/outputs.conf.example`, `dashboards/siem_lab_overview.xml`

---

## 1. Overview & Objectives
- Verify logs flow end-to-end from test generator (Kali) → pfSense → Ubuntu forwarder → Splunk indexer.  
- Confirm `sourcetype` assignment (e.g. `linux:auth`) and field extraction for `src_ip`, `dst_ip`, `dst_port`, `action`.  
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
# while it runs, re-run the nc/ping commands on Kali
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

**Owner:** You
**PRIORITY:** High

### TC1 - Pass/Fail Criteria
- **PASS** if `nc` shows `succeeded` or `Connection refused` (proves reachability) OR tcpdump shows packets from `KALI_IP` to `UBUNTU_IP`.
- **FAIL** if `nc`/tcpdump shows no packets and `No route to host`/`Operation timed out` persists. 

---

### Environment / Variables

```bash

KALI_IP=192.168.60.3
KALI_HOSTNAME=mikeytkali
UBUNTU_HOSTNAME=mikeyt-ubuntu
UBUNTU_IP=192.168.61.10    # forwarder host / Splunk host
INDEXER_IP=192.168.61.10   # Splunk indexer IP
INDEX_PFSENSE=pfsense
INDEX_UBUNTU=ubuntu         # index where host logs land
UF_PORT=9997               # UF -> Indexer port
SYSLOG_PORT=1514           # pfSense -> Splunk syslog port
TIME_WINDOW='Last 15 minutes'