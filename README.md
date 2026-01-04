# Keenetic Firewall 🛡️

High-performance firewall scripts for Keenetic routers (Entware/NDM) that integrate massive IPSET blocklists (e.g., FireHOL) without sacrificing throughput. Includes persistent logging and VPN compatibility.

## 🚀 Features

* **Zero Performance Impact:** Uses kernel `ipset` (hash:net) to block 20,000+ IPs efficiently.
* **Fail-safe Boot:** Includes a smart loader that restores the last known good blocklist if the internet is down at boot.
* **VPN Universal Compatibility:** Automatically whitelists traffic from any VPN interface (`tun+`), supporting both OpenVPN and WireGuard without IP hardcoding.
* **Persistent Statistics:** Tracks total blocked threats over time (Grand Total), surviving router reboots and firewall reloads.
* **Native Integration:** Works as a native NDM (Network Device Manager) netfilter hook.

## 📋 Prerequisites

1.  **Keenetic Router** with **Entware** installed.
2.  Packages: `ipset`, `iptables`, `bash`, `wget`.
    ```bash
    opkg update
    opkg install ipset iptables bash wget
    ```
3.  **Important:** For OpenVPN clients to access the Internet, enable NAT natively on the router via CLI:
    ```bash
    ip nat OpenVPN0
    system configuration save
    ```

## 🛠️ Installation

### 1. Blocklist Loader (Startup)
Downloads the list and loads it into RAM at boot.
Copy `scripts/S00ipset-load` to `/opt/etc/init.d/S00ipset-load` and make it executable.

### 2. Firewall Rules (NDM Hook)
Applies the DROP rules to the router's kernel.
Copy `scripts/100-firewall.sh` to `/opt/etc/ndm/netfilter.d/100-firewall.sh` and make it executable.

### 3. Statistics Logger
Tracks blocked packets and logs to syslog.
Copy `scripts/firewall_stats.sh` to `/opt/bin/firewall_stats.sh` and make it executable.

### 4. Schedule Statistics
Add the logger to crontab to run every hour:
```bash
echo "1 * * * * root /opt/bin/firewall_stats.sh > /dev/null 2>&1" >> /opt/etc/crontab
```

## 📊 How it works
**S00ipset-load**: Starts at boot, creates the FirewallBlock set, downloads the list (default: FireHOL Level 1), sanitizes it, and loads it using ipset restore (milliseconds).

**100-firewall.sh**: Hooks into NDM. It applies DROP rules for the Blacklist on both INPUT (Router protection) and FORWARD (LAN protection), but explicitly allows VPN tunnels (tun+) and LAN traffic (10.0.0.0/8).

**firewall_stats.sh**: Runs hourly. It reads the iptables counters, calculates the delta from the last hour, and updates a persistent "Lifetime Total" file stored on disk.

## 📺 Real-Time Monitor

Includes a dashboard script to view blocking statistics in real-time directly from the terminal.

### Installation
Copy `scripts/firewall_monitor.sh` to `/opt/bin/firewall_monitor` (note: remove extension for easier typing) and make executable:
```bash
cp scripts/firewall_monitor.sh /opt/bin/firewall_monitor
chmod +x /opt/bin/firewall_monitor
```
