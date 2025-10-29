# SIEM Lab Architecture

**Purpose:**  
Document the architecture for the SIEM lab used to ingest pfSense and Ubuntu (host) telemetry, run Kali simulation vulnerability/pen tests, and evaluate detections in Splunk.

**Version:** 0.1  
**Last updated:** 2025-10-28  
**Author:** Micah Thompson

---

## 1. Scope & Assumptions

**Scope**  
This document describes the SIEM lab architecture used for ingesting and analyzing firewall and host telemetry. In-scope components:
- pfSense (edge firewall, syslog source)
- Ubuntu SIEM host running Splunk Enterprise (indexer + search head) and a Universal Forwarder (UF)
- Kali Linux attacker VM used for simulation/testing
- Optional IDS (Suricata) for network-level alerts

Functional scope:
- Collect pfSense syslog to `index=pfsense` (UDP/TCP 1514)
- Collect Ubuntu host logs (`/var/log/syslog`, `/var/log/auth.log`) via UF to `index=ubuntu`
- Provide parsing, field extraction, dashboards, and alerts for recon, port-scanning, brute-force, and beaconing simulations
- Provide a testing playbook and scripts to simulate attacks

Out-of-scope:
- Production network devices and cloud log ingestion
- Enterprise-scale clustering, HA, and long-term archival beyond lab retention settings
- Full Enterprise Security deployment

**Assumptions**
- Lab is isolated from production; all test traffic is limited to the lab VLANs (e.g., `192.168.60.0/29`)
- All VMs and devices have NTP configured and clocks are synchronized
- Splunk (indexer) and UF run the following tested versions: Splunk Enterprise `10.0.1` and Universal Forwarder `10.0.1`
- Minimum resource sizing for the Splunk host: 6 vCPU, 16 GB RAM, 80 GB disk
- Forwarding protocol: Splunk UF → Indexer uses TCP port `9997`; pfSense → Indexer uses TCP/UDP port `1514`
- Tests will be performed against lab VMs only; no production systems will be targeted
- Acceptance criteria: a test syslog or logger message from a forwarder must be indexed and visible in Splunk search within 60 seconds

**Threat model (brief)**  
Adversary: a single lab attacker VM (Kali) performing recon and scanning against lab hosts. Intent: validate detection coverage for scanning/brute-force/beacon patterns. This lab is not configured to emulate advanced persistent adversaries.

## 2. High-level Topology
*(See `diagrams/network-topology.png` for the diagram.)*

**Short summary**  
- pfSense acts as firewall and routes/controls traffic between an **attacker subnet (LabNet)** and a **SIEM subnet (SiemNet / OPT1)**.  
- Kali (attacker) lives on `LabNet`. Ubuntu (SIEM + UF / Splunk) lives on `SiemNet`.  
- pfSense forwards its firewall logs to Splunk; Ubuntu forwards host logs to Splunk via the Splunk Universal Forwarder.  
- Capture points: pfSense SIEMOPT1, pfSense LAN, Ubuntu NIC (and optional IDS sensor).

---

## 3. Components & Roles
- **pfSense (VM)** — edge firewall, DHCP/DNS, generates firewall logs and forwards via syslog to Splunk (UDP/TCP 1514).
- **Ubuntu (SIEM) (VM)** — runs Splunk Universal Forwarder (UF) for local logs and optionally Splunk Enterprise (for lab single-node). Hosts Splunk Enterprise in small-lab config.
- **Splunk Enterprise (server)** — indexer + search head for logs, hosts dashboards and alerts.
- **Kali (VM)** — attacker/tester VM used to generate recon/scans/exploitation attempts.
- **Optional IDS (Suricata/Zeek)** — sensor to generate IDS/HTTP logs forwarded into Splunk. Will be implemented at later phase. 
- **Storage** — host or VM volumes used to store Splunk warm/cold buckets.

---

## 4. Data Flows
- `pfSense -> Splunk Indexer` : syslog -> `index=pfsense`, sourcetype `pfsense:syslog` (UDP/TCP 1514)
- `Ubuntu UF -> Splunk Indexer` : UF TCP -> `index=ubuntu`, sourcetype `linux:auth`, `syslog` (TCP 9997)
- `Optional IDS -> Splunk` : alerts -> `index=ids`, sourcetype `suricata:alert`
- `Splunk internal` : index `_internal` for forwarder/ingest health

---

## 5. Indexing & Retention Policy
- `pfsense` — hot/warm/cold retention default; expected daily ingest ~ X MB; retention = Y days.
- `ubuntu` — retention = Z days; exclude large binary logs; use frozen to archive to external storage/local frozen path.
*(Indexing and Retention TBD)*

---

## 6. Detections, Dashboards & Alerts
- Dashboards: `siem_pfsense_overview`, `siem_ubuntu_host_overview`
- Saved searches / alerts:
  - Port scan detection — trigger when single source scans >50 ports/min
  - SSH brute-force — trigger when >5 failed logins in 10 minutes
  - Beacon detection — repeated DNS queries to same domain >5 times in window

*(See `splunk/savedsearches/port_scan_savedsearch.conf` for implementation)*

---

## 7. Security & Access Control
- Admin accounts limited; Splunk admin uses secure password and is not used for day-to-day analysis, but only for lab purposes.
- Management ports (8000, 8089) restricted to lab-admin network; Splunk mgmt bound to localhost where possible for forwarder-only nodes.
- TLS: None.

---

## 8. Deployment & Config Management
- All Splunk config files (`props.conf.example`, `transforms.conf.example`, `inputs.conf.example`, dashboards) stored in this repo under `configs/` and `splunk/dashboards/`.
- For multiple forwarders, use the Splunk Deployment Server.

---

## 9. Backup & Recovery
- Backup Splunk app configurations (`/opt/splunk/etc/apps/`), `server.conf`, `inputs.conf`.
- Backup indexes if preserving evidence — snapshot VM disks or use Splunk archival to frozen storage.
- Rebuild plan: steps to recreate VMs from ISO/snapshots and reapply repo configs.

---

## 10. Testing & Validation
- Acceptance criteria:
  - Test event from forwarder visible in `index=ubuntu` within 60s.
  - pfSense syslog events indexed in `index=pfsense` and parsed to contain `src_ip` and `dst_port`.
- Test suite:
  - `scripts/simulate_kali.sh` runs a reconnaissance + port scan and checks dashboard hits.
  - Manual test commands listed in `testing_plan.md`.

---

## 11. Monitoring & Health
- Monitor `index=_internal` for `TcpInputProc` and UF connection logs.
- Alerts for:
  - UF disconnect for >10 minutes
  - Indexer disk usage > 80%
  - Index ingestion queue growth

---

## Appendix
- Ports table (see below)  
- Sample config snippets: `configs/pfsense/syslog_to_splunk.example`, `configs/indexer/transforms.conf.example`  
- Change log & version history

---

| Component (source → destination) | Protocol | Port | Purpose |
| ----------------------------------- | ---------| ------ | -------- |
| pfSense → Splunk (syslog) | UDP/TCP | 1514 | pfSense syslog |
| UF → Indexer | TCP | 9997 | UF data forwarding | 
| Splunk UF Mgmt | TCP | 18189 | Splunk UF Management |
| Splunk Web | TCP | 8000 | Splunk UI |
| Splunk Mgmt | TCP | 8089 | Splunk Management |
| SSH (admin) | TCP | 22 | Remote Admin Access |

