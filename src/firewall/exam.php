<?php

/**
 * Exam firewall:
 * - If $enabled === true: for users that currently have an X session, block ALL outbound traffic
 *   except destinations listed in $Configuration['NFS'], ['LDAP'], ['CUSTOM'].
 * - If $enabled === false: remove the exam jump rule (disables exam filtering).
 *
 * Notes:
 * - Uses nftables (inet/filter/output).
 * - Only affects OUTPUT traffic from users in the "exam_uids" set (matched with meta skuid).
 * - “X users” detection
 *
 * $Configuration expected shape (values may be string or array of strings):
 *   $Configuration['NFS']    = ["nfs.server.local", "192.168.10.0/24", ...]
 *   $Configuration['LDAP']   = ["ldap.server.local", "192.168.10.5", ...]
 *   $Configuration['CUSTOM'] = ["repo.school.local", ...]
 *
 */
function firewall_exam(bool $enabled): array
{
    global $Configuration;

    // ---- helpers ----

    $nft = function(string $cmd, ?int &$ret = null): void {
        $ret = 0;
        @system($cmd, $ret);
    };

    $nft_out = function(string $cmd): string {
        $out = @shell_exec($cmd . " 2>/dev/null");
        return is_string($out) ? $out : "";
    };

    $normalize_list = function($v): array {
        if ($v === null) return [];
        if (is_string($v)) return [trim($v)];
        if (is_array($v)) {
            $out = [];
            foreach ($v as $x) {
                if (!is_string($x)) continue;
                $x = trim($x);
                if ($x !== "") $out[] = $x;
            }
            return $out;
        }
        return [];
    };

    $is_ipv4 = fn(string $s): bool => filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $is_ipv6 = fn(string $s): bool => filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

    $is_ipv4_cidr = function(string $s) use ($is_ipv4): bool {
        if (strpos($s, "/") === false) return false;
        [$ip, $pfx] = explode("/", $s, 2);
        if (!$is_ipv4($ip)) return false;
        if ($pfx === "" || preg_match('/^\d+$/', $pfx) !== 1) return false;
        $n = (int)$pfx;
        return $n >= 0 && $n <= 32;
    };

    $is_ipv6_cidr = function(string $s) use ($is_ipv6): bool {
        if (strpos($s, "/") === false) return false;
        [$ip, $pfx] = explode("/", $s, 2);
        if (!$is_ipv6($ip)) return false;
        if ($pfx === "" || preg_match('/^\d+$/', $pfx) !== 1) return false;
        $n = (int)$pfx;
        return $n >= 0 && $n <= 128;
    };

    $resolve_target = function(string $target) use ($is_ipv4, $is_ipv6): array {
        $target = trim($target);
        if ($target === "") return [[], []];

        if ($is_ipv4($target)) return [[$target], []];
        if ($is_ipv6($target)) return [[], [$target]];

        $v4 = [];
        $v6 = [];

        $a = @gethostbynamel($target);
        if (is_array($a)) {
            foreach ($a as $ip) {
                if ($is_ipv4($ip)) $v4[$ip] = true;
            }
        }

        $aaaa = @dns_get_record($target, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $rec) {
                if (isset($rec["ipv6"]) && $is_ipv6($rec["ipv6"])) {
                    $v6[$rec["ipv6"]] = true;
                }
            }
        }

        return [array_keys($v4), array_keys($v6)];
    };

    $usernames_to_uids = function(array $names): array {
        $uids = [];
        foreach ($names as $u) {
            if (!is_string($u) || $u === "") continue;

            if (function_exists("posix_getpwnam")) {
                $pw = @posix_getpwnam($u);
                if (is_array($pw) && isset($pw["uid"])) {
                    $uid = (int)$pw["uid"];
                    if ($uid >= 0) $uids[$uid] = true;
                    continue;
                }
            }

            // Fallback: id -u
            $uid_s = @shell_exec("id -u " . escapeshellarg($u) . " 2>/dev/null");
            if (is_string($uid_s) && preg_match('/^\s*(\d+)\s*$/', $uid_s, $m) === 1) {
                $uid = (int)$m[1];
                if ($uid >= 0) $uids[$uid] = true;
            }
        }
        return array_keys($uids);
    };

    $loginctl_exists = function(): bool {
        // Using `command -v` so PATH mock works in tests.
        $out = @shell_exec("command -v loginctl 2>/dev/null");
        return is_string($out) && trim($out) !== "";
    };

    $get_graphical_usernames = function() use ($loginctl_exists): array {
        if (!$loginctl_exists()) {
            // fallback to `who` with (:0) heuristic
            $out = @shell_exec("who 2>/dev/null");
            if (!is_string($out) || trim($out) === "") return [];
            $users = [];
            foreach (explode("\n", $out) as $line) {
                $line = trim($line);
                if ($line === "") continue;
                if (preg_match('/^(\S+)\s+.*\(\s*:[0-9]+\s*\)\s*$/', $line, $m) === 1) {
                    $users[$m[1]] = true;
                }
            }
            return array_keys($users);
        }

        // Debian/systemd: loginctl list-sessions --no-legend
        $list = @shell_exec("loginctl list-sessions --no-legend 2>/dev/null");
        if (!is_string($list) || trim($list) === "") return [];

        $users = [];
        foreach (explode("\n", $list) as $line) {
            $line = trim($line);
            if ($line === "") continue;

            // Typical: "2 alice seat0  tty2"
            //          "3 bob   seat0  pts/1"
            // We only need session id.
            $parts = preg_split('/\s+/', $line);
            if (!$parts || !isset($parts[0])) continue;
            $sid = $parts[0];

            // Query session details
            $info = @shell_exec("loginctl show-session " . escapeshellarg($sid) . " -p Name -p Type -p Class 2>/dev/null");
            if (!is_string($info) || trim($info) === "") continue;

            $name = null;
            $type = null;
            $class = null;

            foreach (explode("\n", $info) as $kv) {
                $kv = trim($kv);
                if ($kv === "" || strpos($kv, "=") === false) continue;
                [$k, $v] = explode("=", $kv, 2);
                if ($k === "Name")  $name  = $v;
                if ($k === "Type")  $type  = $v;
                if ($k === "Class") $class = $v;
            }

            if ($name === null || $type === null) continue;

            // Consider graphical session if Type is x11 or wayland.
            // (Wayland implies XWayland usually available; you asked to include it.)
            if ($type === "x11" || $type === "wayland") {
                // Some systemd setups also differentiate "user"/"greeter".
                // If Class exists and is "user", good. If absent, accept.
                if ($class === null || $class === "user") {
                    $users[$name] = true;
                }
            }
        }

        return array_keys($users);
    };

    // ---- config -> allowed targets ----

    $nfs    = $normalize_list($Configuration["NFS"]    ?? null);
    $ldap   = $normalize_list($Configuration["LDAP"]   ?? null);
    $custom = $normalize_list($Configuration["CUSTOM"] ?? null);
    $targets = array_values(array_unique(array_filter(array_merge($nfs, $ldap, $custom), fn($x) => $x !== "")));

    // ---- ensure base nft structure ----
    $nft("nft add table inet filter 2>/dev/null || true", $r0);
    $nft("nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true", $r1);
    $nft("nft add chain inet filter exam_out 2>/dev/null || true", $r2);

    $remove_jump = function() use ($nft, $nft_out): void {
        $txt = $nft_out("nft -a list chain inet filter output");
        if ($txt === "") return;

        foreach (explode("\n", $txt) as $line) {
            if (strpos($line, "jump exam_out") === false) continue;
            if (preg_match('/#\s*handle\s+(\d+)/', $line, $m) !== 1) continue;
            $h = (int)$m[1];
            if ($h > 0) {
                $nft("nft delete rule inet filter output handle " . $h . " 2>/dev/null || true", $rr);
            }
        }
    };

    if (!$enabled) {
        $remove_jump();
        return [
            "ok" => true,
            "mode" => "normal",
            "graphical_users" => 0,
            "exam_uids" => 0,
            "allowed_v4" => 0,
            "allowed_v6" => 0,
        ];
    }

    // ---- determine affected users (graphical only) ----
    $graph_users = $get_graphical_usernames();
    $uids        = $usernames_to_uids($graph_users);

    // ---- allowed destination sets ----
    $allow_v4 = [];
    $allow_v6 = [];

    foreach ($targets as $t) {
        $t = trim($t);
        if ($t === "") continue;

        if ($is_ipv4_cidr($t)) { $allow_v4[$t] = true; continue; }
        if ($is_ipv6_cidr($t)) { $allow_v6[$t] = true; continue; }

        [$v4s, $v6s] = $resolve_target($t);
        foreach ($v4s as $ip) $allow_v4[$ip] = true;
        foreach ($v6s as $ip) $allow_v6[$ip] = true;
    }

    $allowV4List = array_keys($allow_v4);
    $allowV6List = array_keys($allow_v6);

    // ---- create/refresh sets ----
    $nft("nft add set inet filter exam_uids '{ type uid; }' 2>/dev/null || true", $r3);
    $nft("nft add set inet filter exam_allow_v4 '{ type ipv4_addr; flags interval; }' 2>/dev/null || true", $r4);
    $nft("nft add set inet filter exam_allow_v6 '{ type ipv6_addr; flags interval; }' 2>/dev/null || true", $r5);

    $nft("nft flush set inet filter exam_uids 2>/dev/null || true", $r6);
    $nft("nft flush set inet filter exam_allow_v4 2>/dev/null || true", $r7);
    $nft("nft flush set inet filter exam_allow_v6 2>/dev/null || true", $r8);

    if (count($uids) > 0) {
        $elems = implode(", ", array_map(fn($u) => (string)(int)$u, $uids));
        $nft("nft add element inet filter exam_uids { " . $elems . " }", $r9);
    }

    if (count($allowV4List) > 0) {
        $elems = implode(", ", $allowV4List);
        $nft("nft add element inet filter exam_allow_v4 { " . $elems . " }", $r10);
    }
    if (count($allowV6List) > 0) {
        $elems = implode(", ", $allowV6List);
        $nft("nft add element inet filter exam_allow_v6 { " . $elems . " }", $r11);
    }

    // ---- program exam_out chain deterministically ----
    $nft("nft flush chain inet filter exam_out 2>/dev/null || true", $r12);
    $nft("nft add rule inet filter exam_out meta skuid @exam_uids ip daddr @exam_allow_v4 accept", $r13);
    $nft("nft add rule inet filter exam_out meta skuid @exam_uids ip6 daddr @exam_allow_v6 accept", $r14);
    $nft("nft add rule inet filter exam_out meta skuid @exam_uids drop", $r15);

    // Ensure jump rule exists once
    $remove_jump();
    $nft("nft add rule inet filter output jump exam_out", $r16);

    return [
        "ok" => true,
        "mode" => "exam",
        "graphical_users" => count($graph_users),
        "exam_uids" => count($uids),
        "allowed_v4" => count($allowV4List),
        "allowed_v6" => count($allowV6List),
    ];
}

