<div align="center">

### ❤️ Support the Project
If you found this project helpful, consider buying me a coffee!

<a href="https://paypal.me/MatteoRosettani">
  <img src="https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate with PayPal" />
</a>

<a href="https://revolut.me/matthew_eli">
  <img src="https://img.shields.io/badge/Revolut-black?style=for-the-badge&logo=revolut&logoColor=white" alt="Donate with Revolut" />
</a>

</div>

# Keenetic Firewall 🛡️

High-performance firewall and monitoring suite for Keenetic routers (Entware/NDM). This suite integrates massive IPSET blocklists, provides real-time traffic analysis, VPN protection, and a rich HTML dashboard with historical data and threat intelligence.

![alt text](https://github.com/mattheweli/keenetic-firewall/raw/main/image.png.e62a0170fd1bc45ffd52f55f3679dd7f.png)

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
opkg install ipset iptables bash wget-ssl curl \
             sqlite3-cli coreutils-date mtr \
             grep awk sed
```
**Note**: `coreutils-date` is crucial for accurate timestamp calculations in the database scripts.

---

## 🛠️ Installation

You can install the suite automatically using **Keentool** (recommended) or manually.

### Option 1: Automatic Installation (Recommended) ⚡
Use **Keentool**, the all-in-one manager, to install, update, and configure the Firewall Suite and its dependencies automatically.

1.  Run the following command in your SSH terminal:
    ```bash
    curl -sL https://raw.githubusercontent.com/mattheweli/keentool/main/keentool -o /opt/bin/keentool && chmod +x /opt/bin/keentool && /opt/bin/keentool
    ```
2.  Select **3. Firewall Suite** from the menu.
3.  Choose **1. Install / Update**.
    * The tool will automatically download scripts, set permissions, and configure Crontab.
    * It will also guide you through setting up the **AbuseIPDB Key**.

---

### Option 2: Manual Installation 🔧

If you prefer to configure everything yourself, follow these steps:

#### 1. Core Firewall (The Engine)
Handles the blocking logic and boot loading.

1.  **Boot Loader:** Copy `scripts/S00ipset-load` to `/opt/etc/init.d/S00ipset-load`.
2.  **Kernel Hook:** Copy `scripts/100-firewall.sh` to `/opt/etc/ndm/netfilter.d/100-firewall.sh`.
3.  **Permissions:**
    ```bash
    chmod +x /opt/etc/init.d/S00ipset-load
    chmod +x /opt/etc/ndm/netfilter.d/100-firewall.sh
    ```

#### 2. Updater & VPN Scanner
Keeps lists fresh and bans VPN attackers.

1.  Copy `scripts/update_blocklist.sh` to `/opt/bin/update_blocklist.sh`.
2.  Copy `scripts/vpn_scan.sh` to `/opt/bin/vpn_scan.sh`.
3.  **Permissions:**
    ```bash
    chmod +x /opt/bin/update_blocklist.sh
    chmod +x /opt/bin/vpn_scan.sh
    ```

#### 3. Statistics & Dashboard
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

#### 4. Terminal Live Monitor (Optional)
Real-time stats in your SSH terminal.

1.  Copy `scripts/firewall_monitor` to `/opt/bin/firewall_monitor` (no extension).
2.  **Permissions:**
    ```bash
    chmod +x /opt/bin/firewall_monitor
    ```

#### 5. Automation (Crontab)
To make everything work automatically, add these lines to your crontab (`/opt/etc/crontab`):

```bash
# 🛡️ Firewall: Update Blocklists (Daily at 04:00)
0 4 * * * root /opt/bin/update_blocklist.sh > /dev/null 2>&1

# 📊 Stats: Generate Dashboard (Every hour at min 01)
1 * * * * root /opt/bin/firewall_stats.sh > /dev/null 2>&1

# 🕵️ VPN: Scan for attackers (Every 3 hours)
0 */3 * * * root /opt/bin/vpn_scan.sh > /dev/null 2>&1
```

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

### Using Keentool
Run the manager at any time to check for updates or manage settings:
```bash
keentool
```

---

# 🛡️ Firewall Manager CLI

The **Firewall Manager** (`firewall_manager.sh`) is the central control panel for the Keenetic Firewall Suite. It allows you to configure security modules, manage blacklists/whitelists, view real-time logs, and generate statistics without needing to edit configuration files manually.

## 🚀 Getting Started

To launch the manager, access your router via SSH and run:

```bash
/opt/bin/firewall_manager.sh
```

> **Note:** Ensure you are running as `root`. The script will automatically load your current configuration from `/opt/etc/firewall.conf`.

---

## 🎮 Main Menu Overview

When you launch the manager, you will see the following options:

### 📊 Monitoring & Stats
* **1) Show Live Monitor:** Opens a real-time log viewer (`firewall_monitor`) showing blocked packets. Press `Ctrl+C` to exit.
* **3) Run Stats & Dashboard:** Manually triggers the statistics engine (`firewall_stats.sh`). This updates the database and the JSON files used by the Web Dashboard. Useful if you want to see immediate changes on the UI.
* **5) Run Abuse Reporter:** Manually triggers the reporting script to send recent attackers to AbuseIPDB (if API key is configured).

### 🔄 Updates & Scanning
* **2) Update Blocklists:** Downloads and refreshes the static IP blocklists (FirewallBlock) from the configured sources.
* **4) Run VPN Scan:** Scans active VPN connections for blacklisted IPs and kicks them if found.

### 🛠️ Operations
* **6) Run Diagnostics:** Performs a system health check. It verifies if:
    * ULOGD logger is running.
    * Cron scheduler is active.
    * Kernel modules (`xt_recent`) are loaded.
    * IP Sets are populated (IPv4/IPv6).
    * IPTables chains are correctly linked.
* **7) Restart Firewall Hook:** Reloads the core firewall rules (`100-firewall.sh`) and applies the current configuration. Use this after manual changes to `.conf` files.
* **9) Manage Whitelist:** Opens the [Whitelist Editor](#-whitelist-management).
* **f) Flush Lists:** Opens the [Flush Menu](#-flush-cleaning) to clear specific lists immediately.

---

## ⚙️ Configuration (Option 8)

The **Settings Menu (Option 8)** allows you to toggle features and tune parameters on the fly.

### 🛡️ Security Modules
* **IPv6 Support:** Toggles IPv6 firewall rules and blocklists.
* **Forward Protection:** If **ON**, the AutoBan trap applies to traffic passing *through* the router (e.g., to a NAS).
    * *Warning:* Ensure your Whitelist is configured before enabling this to avoid blocking legitimate services.
* **AutoBan (Dynamic):** Toggles the "Honeypot" trap. If OFF, port scanners are logged but not banned.
* **BruteForce Protection:** Toggles the `xt_recent` module to ban IPs attempting multiple connections in a short time.
* **DDoS ConnLimit:** Limits the maximum simultaneous connections per source IP (Default: 15).

### 🔧 Tuning & Parameters
* **Auto-Ban Timeout:** Set how long an IP remains banned in the AutoBan list.
    * Supports distinct values (e.g., `3600`) or `0` for Permanent Ban.
    * *Feature:* Changing this applies immediately without a full firewall restart.
* **Brute-Force Sensitivity:** Configure the threshold for banning.
    * *Example:* 5 hits in 60 seconds.
* **Allowed Ports:** Define which TCP/UDP ports are "Open" (Safe). Traffic to any port *not* in this list will trigger the AutoBan trap.
* **AbuseIPDB Settings:** Configure your API Key and set the Reporting Cooldown (default 7 days) to avoid spamming reports.

---

## ✅ Whitelist Management

Accessed via **Option 9**. Use this to prevent you or your services from being blocked.

1.  **Add Entry (a):** Supports:
    * Single IPs (`1.2.3.4`)
    * Subnets/CIDR (`192.168.1.0/24`)
    * Domains (`example.com`) - *Automatically resolves to both IPv4 and IPv6 IPs.*
2.  **Remove Entry (r):** Delete a line from the whitelist.
3.  **Apply (x):** **Crucial Step.** Reloads the whitelist into the running firewall immediately.

---

## 🗑️ Flush (Cleaning)

Accessed via **Option f**. Use this if you accidentally banned yourself or need to clear lists.

* **1) AutoBan:** Clears dynamic bans (Trap).
* **2) FirewallBlock:** Clears downloaded static blocklists.
* **3) VPNBlock:** Clears banned VPN IPs.
* **4) Whitelist:** Clears the trusted list (use with caution).
* **9) FLUSH ALL:** completely empties all IP sets.

---

## 📅 Automation (Cron)

While `firewall_manager.sh` is for manual control, the system relies on `cron` for automation.
**Recommended `crontab` setup** to avoid conflicts between updates and stats generation:

```cron
# Network Monitoring
*/1 * * * * root /opt/bin/pingtool.sh >> /opt/var/log/connmon.log 2>&1

# Stats Generation (Every 30 mins)
*/30 * * * * root /opt/bin/firewall_stats.sh > /dev/null 2>&1

# Blocklist Update (Once a day at 04:15 - Staggered to avoid conflict with stats)
15 4 * * * root /opt/bin/update_blocklist.sh > /dev/null 2>&1

# Security Scans
15 * * * * root /opt/bin/vpn_scan.sh > /dev/null 2>&1
45 * * * * root /opt/bin/abuse_reporter.sh > /dev/null 2>&1
```

---

## 🤝 Compatibility
Designed for **KeeneticOS** routers running **Entware**.
