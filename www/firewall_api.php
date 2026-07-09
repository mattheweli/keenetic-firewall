<?php
// ==============================================================================
// KEENETIC FIREWALL API BACKEND v1.0.0
// ==============================================================================
// AUTHOR: mattheweli
// DESCRIPTION: 
//   This script acts as the backend API for the Keenetic Firewall Dashboard.
//   It processes JSON requests to safely interact with IP sets and iptables 
//   on the router.
//
//   FEATURES:
//     - IPv4/IPv6 format validation.
//     - Real-time IP lookup across multiple blocklists (AutoBan, GeoBlock, etc.).
//     - Manual IP ban functionality with instant disk persistence.
//     - Quick IP unban (from both AutoBan and manual Blacklists).
//     - Global Master Switch control to enable/disable the firewall on the fly.
// ==============================================================================

// /opt/var/www/firewall/firewall_api.php
header('Content-Type: application/json');

$action = isset($_GET['action']) ? $_GET['action'] : '';
$raw_ip = isset($_GET['ip']) ? trim($_GET['ip']) : '';

/**
 * Manual IP validation (without depending on filter_var)
 * Supports IPv4 and basic IPv6 format
 */
function isIPValid($ip) {
    // Basic IPv4 format validation
    if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $ip)) {
        // If not v4, check basic v6
        return (strpos($ip, ':') !== false);
    }
    
    // NEW: Lifesaver filter to prevent banning crucial internal/local IPs
    // Blocks 127.x.x.x, Multicast (224.x-255.x), and Broadcast (255.255.255.255)
    if (preg_match('/^(127\.|224\.|225\.|239\.|255\.255\.255\.255)/', $ip)) {
        return false;
    }
    
    return true;
}

// Validate IP format if provided
if (!empty($raw_ip) && !isIPValid($raw_ip)) {
    echo json_encode(["status" => "error", "message" => "Invalid IP format: $raw_ip"]);
    exit;
}

// Safely escape IP for shell execution
$safe_ip = escapeshellarg($raw_ip);

switch ($action) {
    case 'lookup':
        if (empty($raw_ip)) {
            echo json_encode(["status" => "error", "message" => "IP required"]);
        } else {
            // Define ipsets to check (Added new manual Blacklists)
            $sets = ['AutoBan', 'Blacklist', 'GeoBlock', 'FirewallBlock', 'AutoBan6', 'Blacklist6', 'FirewallBlock6']; 
            $found_in = [];

            foreach ($sets as $set) {
                // Verify if the ipset exists to prevent errors
                $exists = shell_exec("ipset list " . escapeshellarg($set) . " 2>/dev/null");
                if ($exists) {
                    // Test if IP is in the set
                    $check = shell_exec("ipset test " . escapeshellarg($set) . " $safe_ip 2>&1");
                    if (strpos($check, 'is in set') !== false) {
                        $found_in[] = $set;
                    }
                }
            }

            echo json_encode([
                "status" => "success", 
                "ip" => $raw_ip, 
                "blocked" => count($found_in) > 0,
                "lists" => $found_in
            ]);
        }
        break;

    case 'ban':
        if (empty($raw_ip)) {
            echo json_encode(["status" => "error", "message" => "IP required"]);
        } else {
            // Determine if IPv4 or IPv6 and select the appropriate manual list
            $target_list = (strpos($raw_ip, ':') !== false) ? 'Blacklist6' : 'Blacklist';
            
            // Execute the ban directly via shell
            shell_exec("ipset add " . escapeshellarg($target_list) . " $safe_ip 2>/dev/null");
            
            // NEW: Save the list to disk instantly for persistence
            shell_exec("ipset save " . escapeshellarg($target_list) . " > /opt/etc/" . escapeshellarg($target_list) . ".backup");
            
            echo json_encode(["status" => "success", "action" => $action, "ip" => $raw_ip, "list" => $target_list]);
        }
        break;

    case 'unban':
        if (empty($raw_ip)) {
            echo json_encode(["status" => "error", "message" => "IP required"]);
        } else {
            // Unban from both AutoBan and manual Blacklist to ensure it's fully freed
            $target_lists = (strpos($raw_ip, ':') !== false) ? ['AutoBan6', 'Blacklist6'] : ['AutoBan', 'Blacklist'];
            
            foreach ($target_lists as $list) {
                shell_exec("ipset del " . escapeshellarg($list) . " $safe_ip 2>/dev/null");
                
                // NEW: Save the list to disk instantly to prevent the IP from returning on reboot
                shell_exec("ipset save " . escapeshellarg($list) . " > /opt/etc/" . escapeshellarg($list) . ".backup");
            }
            
            echo json_encode(["status" => "success", "action" => $action, "ip" => $raw_ip]);
        }
        break;

    case 'status':
        // Read config and check if the Master Kill Switch is enabled
        $conf = @file_get_contents('/opt/etc/firewall.conf');
        $enabled = true; // Assume enabled by default
        if ($conf !== false && preg_match('/^ENABLE_FIREWALL="false"/m', $conf)) {
            $enabled = false;
        }
        echo json_encode(["status" => "success", "enabled" => $enabled]);
        break;

    case 'enable':
        // 1. In-place edit of the config file
        shell_exec("sed -i 's/^ENABLE_FIREWALL=\"false\"/ENABLE_FIREWALL=\"true\"/' /opt/etc/firewall.conf");
        // 2. Call the native hook bypassing the table check, run in background to prevent UI lag
        shell_exec("table=filter /opt/bin/100-firewall.sh >/dev/null 2>&1 &");
        
        echo json_encode(["status" => "success", "action" => "enable"]);
        break;

    case 'disable':
        // 1. In-place edit of the config file
        shell_exec("sed -i 's/^ENABLE_FIREWALL=\"true\"/ENABLE_FIREWALL=\"false\"/' /opt/etc/firewall.conf");
        // 2. Call the native hook to flush chains cleanly
        shell_exec("table=filter /opt/bin/100-firewall.sh >/dev/null 2>&1 &");
        
        echo json_encode(["status" => "success", "action" => "disable"]);
        break;
		
	case 'livelog':
        $pcap_file = '/tmp/fw_syn_ring.pcap';
        // Get line count from request, default to 1000 if not provided
        $lines = isset($_GET['lines']) ? intval($_GET['lines']) : 1000;
        
        if (!file_exists($pcap_file) || filesize($pcap_file) === 0) {
            echo json_encode(["status" => "error", "message" => "No packets captured (PCAP empty or missing)."]);
            exit;
        }

        // Use tcpdump to read binary pcap, -nn for no DNS resolution
        // Use tail to limit output lines based on user preference
        $cmd = "tcpdump -nn -r " . escapeshellarg($pcap_file) . " 2>/dev/null | tail -n " . intval($lines);
        $log_data = shell_exec($cmd);

        if (empty($log_data)) {
            echo json_encode(["status" => "success", "log" => "Waiting for packets..."]);
        } else {
            echo json_encode(["status" => "success", "log" => $log_data]);
        }
        break;

    default:
        echo json_encode(["status" => "error", "message" => "Invalid action"]);
        break;
}