| Component (source → destination) | Protocol | Port | Purpose |
| ----------------------------------- | ---------| ------ | -------- |
| UF → Indexer | TCP | 9997 | UF data forwarding | 
| pfSense → Splunk (syslog) | UDP/TCP | 1514 | pfSense syslog |
| Splunk Web | TCP | 8000 | Splunk UI |
| Splunk Mgmt | TCP | 8089 | Splunk Management |
| Splunk UF Mgmt | TCP | 18189 | Splunk UF Management |
| SSH (admin) | TCP | 22 | Remote Admin Access |

# SIEM Lab Architecture

**Purpose:**  
Document the architecture for the SIEM lab used to ingest pfSense and Ubuntu (host) telemetry, run Kali simulation vulnerability/pen tests, and evaluate detections in Splunk.

**Version:** 0.1  
**Last updated:** 2025-10-27  
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
- Collect Ubuntu host logs (`/var/log/syslog`, `/var/log/auth.log`) via UF to `index=hosts`
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

