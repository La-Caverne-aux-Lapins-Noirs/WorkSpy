<?php
declare(strict_types=1);

/*
 * Persoc -> Infosphere Hand: send activity packet for log_activity command.
 *
 * Requires:
 * - send_data() + hand_packet() available (e.g. require src/hand/send_data.php)
 * - global $Configuration["InfosphereHand"] set to the IH host
 */

function persoc_parse_duration(string $idle): int
{
    $idle = trim($idle);
    if ($idle === '.' || $idle === '')
        return 0;

    // "123s" or "123.45s"
    if (preg_match('/^([0-9]+)(\.[0-9]+)?s$/', $idle, $m))
        return (int)$m[1];

    // "MM:SS" (w idle often), or "HH:MM" (sometimes)
    if (preg_match('/^([0-9]+):([0-9]+)$/', $idle, $m))
        return ((int)$m[1] * 60 + (int)$m[2]);

    // "HH:MM:SS"
    if (preg_match('/^([0-9]+):([0-9]+):([0-9]+)$/', $idle, $m))
        return ((int)$m[1] * 3600 + (int)$m[2] * 60 + (int)$m[3]);

    // "DD-HH:MM:SS" (ps etime can be like 1-02:03:04)
    if (preg_match('/^([0-9]+)-([0-9]+):([0-9]+):([0-9]+)$/', $idle, $m))
        return ((int)$m[1] * 86400 + (int)$m[2] * 3600 + (int)$m[3] * 60 + (int)$m[4]);

    return 0;
}

function persoc_is_user_lock(string $user): int
{
    $user = trim($user);
    if ($user === "")
        return 0;

    // Strict-ish: parse ps output, match xtrlock-pam command
    $lst = @shell_exec("ps -eo user,pid,etime,cmd 2>/dev/null | grep xtrlock-pam | grep " . escapeshellarg($user) . " | grep -v grep | tr -s ' '");
    if (!is_string($lst) || trim($lst) === "")
        return 0;

    foreach (explode("\n", trim($lst)) as $l)
    {
        $l = trim($l);
        if ($l === "") continue;

        $parts = explode(" ", $l);
        // expected: user pid etime cmd...
        if (count($parts) >= 4 && preg_match('/^xtrlock-pam(\s|$)/', $parts[3]))
            return persoc_parse_duration($parts[2]);
    }
    return 0;
}

/**
 * Returns array of:
 *  - username (string)
 *  - mode ("x" | "ssh")
 *  - lock (bool)
 *  - last_activity (string "d/m/Y H:i:s")
 */
function persoc_users_get_activity(): array
{
    $users = [];

    // Classic `w` parsing (kept for compatibility / simplicity)
    $lst = @shell_exec("PROCPS_USERLEN=32 w 2>/dev/null | tr -s ' '");
    if (!is_string($lst) || trim($lst) === "")
        return $users;

    $lines = explode("\n", $lst);

    // Drop header lines (as your legacy code did)
    if (count($lines) >= 2) {
        array_shift($lines);
        array_shift($lines);
    }

    // Remove trailing empty
    while (count($lines) && trim(end($lines)) === "")
        array_pop($lines);

    $now = time();

    foreach ($lines as $l)
    {
        $l = trim($l);
        if ($l === "") continue;

        $cols = explode(" ", $l);
        // Minimal sanity: expect at least idle column
        if (count($cols) < 5) continue;

        $username = $cols[0];
        $fromOrTty = $cols[2];
        $idle = $cols[4];

        if (filter_var($fromOrTty, FILTER_VALIDATE_IP))
        {
            // SSH user
            $last = $now - persoc_parse_duration($idle);
            $users[] = [
                "username" => $username,
                "mode" => "ssh",
                "lock" => false,
                "last_activity" => date("d/m/Y H:i:s", $last),
            ];
        }
        else
        {
            // X (or local tty) user, we treat it as "x" for IH contract
            $lockAge = persoc_is_user_lock($username);
            if ($lockAge > 0) {
                $last = $now - $lockAge;
                $users[] = [
                    "username" => $username,
                    "mode" => "x",
                    "lock" => true,
                    "last_activity" => date("d/m/Y H:i:s", $last),
                ];
            } else {
                $users[] = [
                    "username" => $username,
                    "mode" => "x",
                    "lock" => false,
                    "last_activity" => date("d/m/Y H:i:s", $now),
                ];
            }
        }
    }

    return $users;
}

/**
 * Determine (iface, ip, mac) from `ip` command, without /sys.
 * @return array{iface:string, ip:string, mac:string}|null
 */
function persoc_get_net_identity(): ?array
{
    // Pick route to internet to determine iface + src IP
    $route = @shell_exec("ip route get 1.1.1.1 2>/dev/null");
    if (!is_string($route) || trim($route) === "")
        return null;

    // Parse: "... dev eth0 src 192.168.1.50 ..."
    $iface = null;
    $ip = null;

    if (preg_match('/\bdev\s+([a-zA-Z0-9_.:-]+)\b/', $route, $m))
        $iface = $m[1];
    if (preg_match('/\bsrc\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b/', $route, $m))
        $ip = $m[1];

    if (!$iface || !$ip)
        return null;

    // MAC from ip link
    $link = @shell_exec("ip link show dev " . escapeshellarg($iface) . " 2>/dev/null");
    if (!is_string($link) || trim($link) === "")
        return null;

    $mac = null;
    if (preg_match('/\blink\/ether\s+([0-9a-fA-F:]{17})\b/', $link, $m))
        $mac = strtolower($m[1]);

    if (!$mac)
        return null;

    return ["iface" => $iface, "ip" => $ip, "mac" => $mac];
}

/**
 * Best-effort machine "type" (string required by IH log_activity).
 * You can refine later; for now: ID from /etc/os-release else "linux".
 */
function persoc_get_machine_type(): string
{
    $osr = @file_get_contents("/etc/os-release");
    if (is_string($osr)) {
        if (preg_match('/^ID=([a-zA-Z0-9._-]+)\s*$/m', $osr, $m))
            return $m[1];
    }
    return "linux";
}

/**
 * Main function: sends the packet to IH log_activity.
 * No params: host is $Configuration["InfosphereHand"].
 *
 * @return array|null decoded JSON from IH (send_data semantics)
 */
function users_log_activity(): ?array
{
    global $Configuration;

    if (!isset($Configuration["InfosphereHand"]) || !is_string($Configuration["InfosphereHand"]) || trim($Configuration["InfosphereHand"]) === "")
        return null;

    $id = persoc_get_net_identity();
    if ($id === null)
        return null;

    $name = @shell_exec("hostname 2>/dev/null");
    $name = is_string($name) ? trim($name) : "";
    if ($name === "")
        $name = "unknown";

    $packet = [
        "command" => "log_activity",
        "date" => date("d/m/Y H:i:s"),
        "mac" => $id["mac"],
        "name" => $name,
        "ip" => $id["ip"],
        "type" => persoc_get_machine_type(),
        "users" => persoc_users_get_activity(),
    ];

    return send_data($Configuration["InfosphereHand"], $packet);
}
