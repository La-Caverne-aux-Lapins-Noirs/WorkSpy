<?php

/**
 * Apply Persoc deadlist (block outbound connections to listed sites) using nftables.
 *
 * deadlist.csv format (CSV):
 *   first column: hostname OR IP (v4/v6)
 *   other columns optional (reason, notes...)
 *
 * Example:
 *   example.com,malware
 *   1.2.3.4,ads
 *   # comment
 *
 * Requires: nft (nftables) + permissions to run it.
 */
function firewall_deadlist(string $csvPath = "/etc/persoc/deadlist.csv"): array
{
    if (!is_readable($csvPath))
        return ([
            "ok" => false,
            "error" => "deadlist not readable: " . $csvPath,
            "blocked_v4" => 0,
            "blocked_v6" => 0,
            "entries" => 0,
        ]);

    $raw = file($csvPath, FILE_IGNORE_NEW_LINES);
    if ($raw === false)
        return ([
            "ok" => false,
            "error" => "cannot read deadlist: " . $csvPath,
            "blocked_v4" => 0,
            "blocked_v6" => 0,
            "entries" => 0,
        ]);

    $v4 = [];
    $v6 = [];
    $entries = 0;

    foreach ($raw as $line)
    {
        $line = trim($line);
        if ($line === "" || str_starts_with($line, "#"))
            continue;

        // Parse CSV (first field only)
        $cols = str_getcsv($line);
        if (!$cols || !isset($cols[0]))
            continue;

        $target = trim($cols[0]);
        if ($target === "")
            continue;

        $entries++;

        // If already an IP, store it directly.
        if (filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
	{
            $v4[$target] = true;
            continue;
        }
        if (filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
	{
            $v6[$target] = true;
            continue;
        }

        // Otherwise, resolve hostname to A/AAAA.
        // A records (IPv4)
        $a = @gethostbynamel($target);
        if (is_array($a))
            foreach ($a as $ip)
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
                    $v4[$ip] = true;

        // AAAA records (IPv6)
        $aaaa = @dns_get_record($target, DNS_AAAA);
        if (is_array($aaaa))
            foreach ($aaaa as $rec)
                if (isset($rec["ipv6"]) && filter_var($rec["ipv6"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
                    $v6[$rec["ipv6"]] = true;
    }
	
    // Convert to flat arrays
    $v4List = array_keys($v4);
    $v6List = array_keys($v6);

    // --- nftables setup (idempotent) ---
    // We assume your firewall_reset already did:
    //   nft flush ruleset; nft add table inet filter
    //
    // Here, we ensure output chain + sets + rules exist and refresh set contents.

    $cmds = [];

    // Ensure table exists (safe if already there; ignore errors with "2>/dev/null || true")
    $cmds[] = "nft add table inet filter 2>/dev/null || true";

    // Ensure output chain exists
    $cmds[] = "nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true";

    // Ensure sets exist (one v4, one v6)
    $cmds[] = "nft add set inet filter deadlist_v4 '{ type ipv4_addr; flags interval; }' 2>/dev/null || true";
    $cmds[] = "nft add set inet filter deadlist_v6 '{ type ipv6_addr; flags interval; }' 2>/dev/null || true";

    // Flush set contents (but keep sets)
    $cmds[] = "nft flush set inet filter deadlist_v4 2>/dev/null || true";
    $cmds[] = "nft flush set inet filter deadlist_v6 2>/dev/null || true";

    // Refill sets
    if (count($v4List) > 0)
    {
        $elems = implode(", ", array_map(fn($ip) => $ip, $v4List));
        $cmds[] = "nft add element inet filter deadlist_v4 { " . $elems . " }";
    }
    if (count($v6List) > 0)
    {
        $elems = implode(", ", array_map(fn($ip) => $ip, $v6List));
        $cmds[] = "nft add element inet filter deadlist_v6 { " . $elems . " }";
    }

    // Ensure rules exist (only add if not already present)
    // Rule names are not always available; we check with grep on 'nft list chain'
    // and add if missing.
    $cmds[] =
        "nft list chain inet filter output 2>/dev/null | grep -q 'ip daddr @deadlist_v4 drop' || " .
        "nft add rule inet filter output ip daddr @deadlist_v4 drop"
	;
    $cmds[] =
        "nft list chain inet filter output 2>/dev/null | grep -q 'ip6 daddr @deadlist_v6 drop' || " .
        "nft add rule inet filter output ip6 daddr @deadlist_v6 drop"
	;

    // Execute commands
    $ok = true;
    $errors = [];
    foreach ($cmds as $c)
    {
        // shell-safe execution: command is fixed; only IPs are injected, but they are validated above.
        $ret = 0;
        @system($c, $ret);
        if ($ret !== 0)
	{
            // Many commands are "|| true"; ret here means a real failure.
            // We still record it.
            $ok = false;
            $errors[] = $c;
        }
    }

    return ([
        "ok" => $ok,
        "error" => $ok ? "" : ("nft errors on: " . implode(" | ", $errors)),
        "blocked_v4" => count($v4List),
        "blocked_v6" => count($v6List),
        "entries" => $entries,
    ]);
}
