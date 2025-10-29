# SIEM Lab Test Plan

**Purpose:**  
Repeatable, versioned tests to verify end-to-end ingestion, parsing/normalization, dashboards, and alerts for the lab (pfSense → Ubuntu Splunk UF → Splunk indexer).

- **Author:** Micah Thompson 
- **Date:** 2025-10-28  
- **Version:** 0.1  
- **Related docs:** `architecture.md`, `configs/forwarder/inputs.conf.example`, `configs/forwarder/outputs.conf.example`, `dashboards/siem_lab_overview.xml`

---

## 1. Overview & Objectives
- Verify logs flow end-to-end from test generator (Kali) → pfSense → Ubuntu forwarder → Splunk indexer.  
- Confirm `sourcetype` assignment (e.g. `linux:auth`) and field extraction for `src_ip`, `dst_ip`, `dst_port`, `action`.  
- Validate dashboard panels and saved-search alerts (recon, port scans, SSH brute force).  
- Provide reproducible steps, expected outcomes, and troubleshooting commands.

---

### TC1 — Network reachability (Kali → Ubuntu)

**Objective:**  
Verify basic network reachability from Kali to the Ubuntu target (the host running the UF / Splunk or the SIEM target). This proves VMs are on the expected internal networks and common ports respond as expected.

**Preconditions**
- `ENV` block in this doc populated (`KALI_IP`, `UBUNTU_IP`, `INDEXER_IP`, etc.).
- VMs powered on and connected to the correct VirtualBox internal networks (e.g., `LabNet`, `SiemNet`).
- pfSense rules allow traffic between Kali and Ubuntu (or pfSense not in the path for the chosen internal network).
- You have a terminal on Kali and a terminal on Ubuntu (target/indexer).

**Steps**
1. On **Kali**: confirm IP and interfaces.
```bash
hostname && ip -br addr > evidence/tc1-kali-ip-$(date +%Y%m%dT%H%M%S).log
cat evidence/tc1-kali-ip-*.log
```

2. On Ubuntu: confirm IP and interfaces. 
```bash
hostname && ip -br addr > evidence/tc1-ubuntu-ip-$(date +%Y%m%dT%H%M%S).log
cat evidence/tc1-ubuntu-ip-*.log
```

3. From Kali: test TCP connectivity to common target ports (no DNS lookups).

## Environment / Variables

```bash

KALI_IP=192.168.60.3
KALI_HOSTNAME=mikeytkali
UBUNTU_HOSTNAME=mikeyt-ubuntu
UBUNTU_IP=192.168.61.10    # forwarder host / Splunk host (if same as indexer)
INDEXER_IP=192.168.61.10   # Splunk indexer IP (replace if different)
INDEX_PFSENSE=pfsense
INDEX_UBUNTU=ubuntu         # index where host logs land (e.g., ubuntu or hosts)
UF_PORT=9997               # UF -> Indexer port (default 9997)
SYSLOG_PORT=1514           # pfSense -> Splunk syslog port (e.g., 1514)
TIME_WINDOW='Last 15 minutes'