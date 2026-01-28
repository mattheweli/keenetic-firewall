<div align="center">

### ❤️ Support the Project
If you found this project helpful, consider buying me a coffee!

<a href="https://revolut.me/matthew_eli">
  <img src="https://img.shields.io/badge/Revolut-black?style=for-the-badge&logo=revolut&logoColor=white" alt="Donate with Revolut" />
</a>

</div>

# Keenetic Firewall 🛡️📊

High-performance firewall and monitoring suite for Keenetic routers (Entware/NDM). This suite integrates massive IPSET blocklists, provides real-time traffic analysis, VPN protection, and a rich HTML dashboard with historical data and threat intelligence.

## 🚀 Features

### 🔥 Core Firewall
* **Zero Performance Impact:** Uses kernel `ipset` (hash:net) to block 20,000+ IPs efficiently.
* **Fail-safe Boot:** Smart loader restores the last known good blocklist if the internet is down at boot.
* **Smart Updates:** Daily updates with deduplication and "Zero Downtime" swapping.
* **VPN Compatibility:** Automatically handles VPN interfaces (`tun+`) and excludes LAN traffic.

### 📊 Intelligence & Statistics
* **Rich HTML Dashboard:** Visualizes traffic with Chart.js (Hourly/Daily/Monthly stats).
* **Threat Intelligence:** Integrates **AbuseIPDB** API to identify and geolocate top threats.
* **SQLite Backend:** Stores historical data efficiently for long-term trend analysis.
* **VPN Protection:** Scans logs for OpenVPN brute-force attacks and bans attackers dynamically.

### 📡 Network Monitoring
* **Real-Time Terminal Monitor:** A `top`-like interface for your firewall to see dropped packets in real-time.

---

## 📋 Prerequisites

1.  **Keenetic Router** with **Entware** installed.
2.  **Web Server** (Optional but recommended): A web server (like `lighttpd` or `nginx`) running on Entware is required to view the HTML dashboards.
3.  **Dependencies:** Install the following packages via SSH:

```bash
opkg update
opkg install ipset iptables bash wget curl \
             sqlite3-cli coreutils-date mtr \
             grep awk sed
```
**Note**: coreutils-date is crucial for accurate timestamp calculations in the database scripts.

---

## 🛠️ Installation

### 1. Core Firewall (The Engine)
Handles the blocking logic and boot loading.

1.  **Boot Loader:** Copy `scripts/S00ipset-load` to `/opt/etc/init.d/S00ipset-load`.
2.  **Kernel Hook:** Copy `scripts/100-firewall.sh` to `/opt/etc/ndm/netfilter.d/100-firewall.sh`.
3.  **Permissions:**
    ```bash
    chmod +x /opt/etc/init.d/S00ipset-load
    chmod +x /opt/etc/ndm/netfilter.d/100-firewall.sh
    ```

### 2. Updater & VPN Scanner
Keeps lists fresh and bans VPN attackers.

1.  Copy `scripts/update_blocklist.sh` to `/opt/bin/update_blocklist.sh`.
2.  Copy `scripts/vpn_scan.sh` to `/opt/bin/vpn_scan.sh`.
3.  **Permissions:**
    ```bash
    chmod +x /opt/bin/update_blocklist.sh
    chmod +x /opt/bin/vpn_scan.sh
    ```
### 3. Statistics & Dashboard
Generates the HTML dashboard.

1.  Copy `scripts/firewall_stats.sh` to `/opt/bin/firewall_stats.sh`.
2.  **Configuration:** Edit the file and add your **AbuseIPDB Key**:
    ```bash
    ABUSEIPDB_KEY="your_api_key_here"
    ```
3.  **Permissions:**
    ```bash
    chmod +x /opt/bin/firewall_stats.sh
    ```

### 4. Terminal Live Monitor (Optional)
Real-time stats in your SSH terminal.

1.  Copy `scripts/firewall_monitor` to `/opt/bin/firewall_monitor` (no extension).
2.  **Permissions:**
    ```bash
    chmod +x /opt/bin/firewall_monitor
    ```

---

## ⏰ Automation (Crontab)

To make everything work automatically, add these lines to your crontab (`/opt/etc/crontab`):

```bash
# 🛡️ Firewall: Update Blocklists (Daily at 04:00)
0 4 * * * root /opt/bin/update_blocklist.sh > /dev/null 2>&1

# 📊 Stats: Generate Dashboard (Every hour at min 01)
1 * * * * root /opt/bin/firewall_stats.sh > /dev/null 2>&1

# 🕵️ VPN: Scan for attackers (Every 3 hours)
0 */3 * * * root /opt/bin/vpn_scan.sh > /dev/null 2>&1

---

## 🖥️ Usage

### Viewing the Dashboard
If you have a web server set up pointing to `/opt/var/www/`, access:
* **Firewall Stats:** `http://router-ip:port/firewall/`

### Using the Live Monitor
Simply run from your SSH terminal:
```bash
firewall_monitor
```
Shows real-time drops, session statistics, and the top 5 active blocked sources.

---

## 📂 File Structure

* `/opt/etc/firewall_stats.db`: SQLite database for stats.
* `/opt/var/www/firewall/`: Generated HTML/JSON files for Firewall.
* `/opt/etc/vpn_banned_ips.txt`: Persistent list of locally banned VPN attackers.

---

## 🤝 Compatibility
Designed for **KeeneticOS** routers running **Entware**.
