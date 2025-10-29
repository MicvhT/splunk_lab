# SIEM Lab Test Plan

**Purpose:**  
Repeatable, versioned tests to verify end-to-end ingestion, parsing/normalization, dashboards, and alerts for the lab (pfSense → Ubuntu Splunk UF → Splunk indexer).


```bash
# ENV - edit before running tests
KALI_IP=192.168.60.10
KALI_HOSTNAME=kali
UBUNTU_HOSTNAME=mikeyt-ubuntu
UBUNTU_IP=192.168.61.10    # forwarder host / Splunk host (if same as indexer)
INDEXER_IP=192.168.61.10   # Splunk indexer IP (replace if different)
INDEX_PFSENSE=pfsense
INDEX_HOSTS=ubuntu         # index where host logs land (e.g., ubuntu or hosts)
UF_PORT=9997               # UF -> Indexer port (default 9997)
SYSLOG_PORT=1514           # pfSense -> Splunk syslog port (e.g., 1514)
TIME_WINDOW='Last 15 minutes'
ADMIN_EMAIL=you@example.com