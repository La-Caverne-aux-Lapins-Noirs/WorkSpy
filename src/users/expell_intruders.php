<?php
declare(strict_types=1);

/*
 * Persoc: expel intruders depending on exam mode (Infosphere Hand is_exam).
 *
 * Rules:
 * - Ask Infosphere Hand if exam mode is on for THIS machine (mac-based room mapping).
 * - If exam == true:
 *     close all graphical sessions (x11/wayland) whose username is NOT a.b.exam
 * - If exam == false:
 *     close all graphical sessions (x11/wayland) whose username IS a.b.exam
 *
 * Additional requirement:
 * - Infosphere Hand will provide a "start_at" field (future).
 * - If exam starts in less than 5 minutes:
 *     broadcast a warning message to ALL graphical users (wall)
 *     but only when current seconds == 00 (to avoid spam).
 *
 * No parameters. Host is in $Configuration["InfosphereHand"].
 * Needs send_data() available.
 */

function persoc_now(): int
{
    // For tests: allow deterministic time without adding function params.
    $v = getenv("PERSOC_NOW");
    if (is_string($v) && preg_match('/^\d+$/', $v) === 1)
        return (int)$v;
    return time();
}

/** a.b.exam */
function persoc_is_exam_account(string $username): bool
{
    return preg_match('/^[^.]+\.[^.]+\.exam$/', $username) === 1;
}

/** Debian/systemd: list graphical users via loginctl (x11/wayland); fallback to who heuristic. */
function persoc_list_graphical_sessions(): array
{
    $out = @shell_exec("command -v loginctl 2>/dev/null");
    $hasLoginctl = is_string($out) && trim($out) !== "";

    $sessions = []; // each: ["sid"=>string,"user"=>string,"type"=>string]

    if ($hasLoginctl)
    {
        $list = @shell_exec("loginctl list-sessions --no-legend 2>/dev/null");
        if (is_string($list) && trim($list) !== "")
        {
            foreach (explode("\n", trim($list)) as $line)
            {
                $line = trim($line);
                if ($line === "") continue;

                $parts = preg_split('/\s+/', $line);
                if (!$parts || !isset($parts[0])) continue;
                $sid = $parts[0];

                $info = @shell_exec("loginctl show-session " . escapeshellarg($sid) . " -p Name -p Type -p Class 2>/dev/null");
                if (!is_string($info) || trim($info) === "") continue;

                $name = null;
                $type = null;
                $class = null;

                foreach (explode("\n", trim($info)) as $kv)
                {
                    $kv = trim($kv);
                    if ($kv === "" || strpos($kv, "=") === false) continue;
                    [$k, $v] = explode("=", $kv, 2);
                    if ($k === "Name")  $name  = $v;
                    if ($k === "Type")  $type  = $v;
                    if ($k === "Class") $class = $v;
                }

                if ($name === null || $type === null) continue;
                if ($class !== null && $class !== "user") continue;

                if ($type === "x11" || $type === "wayland")
                    $sessions[] = ["sid" => (string)$sid, "user" => (string)$name, "type" => (string)$type];
            }
            return $sessions;
        }
        // if loginctl exists but returned nothing, fall back below
    }

    // Fallback: who lines with (:0) etc. (no session id available)
    $who = @shell_exec("who 2>/dev/null");
    if (!is_string($who) || trim($who) === "")
        return [];

    $seen = [];
    foreach (explode("\n", trim($who)) as $line)
    {
        $line = trim($line);
        if ($line === "") continue;
        if (preg_match('/^(\S+)\s+.*\(\s*:[0-9]+\s*\)\s*$/', $line, $m) === 1)
            $seen[$m[1]] = true;
    }

    foreach (array_keys($seen) as $u)
        $sessions[] = ["sid" => "", "user" => $u, "type" => "x11"];

    return $sessions;
}

/** Terminate a graphical session (prefer loginctl by session id; fallback to pkill -KILL -u user). */
function persoc_kill_graphical_session(string $sid, string $user): void
{
    global $Configuration;
    
    if (@$Configuration["LocalUser"] && $user == $Configuration["LocalUser"])
	return ;
    $user = trim($user);
    $sid  = trim($sid);

    $out = @shell_exec("command -v loginctl 2>/dev/null");
    $hasLoginctl = is_string($out) && trim($out) !== "";

    if ($hasLoginctl && $sid !== "")
    {
        // terminate-session is clean; kill-session exists too.
        @system("loginctl terminate-session " . escapeshellarg($sid) . " 2>/dev/null", $ret);
        return;
    }

    if ($user !== "")
    {
        // Fallback: harsh but effective; will kill all processes of the user.
        // Use only if we don't have a session id (older fallback path).
        @system("pkill -KILL -u " . escapeshellarg($user) . " 2>/dev/null", $ret);
    }
}

/** Parse start_at from IH response; accept int unix or strtotime-compatible string. Returns unix timestamp or null. */
function persoc_parse_start_at($start_at): ?int
{
    if (is_int($start_at))
        return $start_at;

    if (is_string($start_at))
    {
        $s = trim($start_at);
        if ($s === "") return null;

        if (preg_match('/^\d+$/', $s) === 1)
            return (int)$s;

        $t = strtotime($s);
        if ($t !== false)
            return (int)$t;
    }

    return null;
}

/** get mac/ip without parameters; minimal for is_exam query (mac required). */
function persoc_get_net_identity_for_exam(): ?array
{
    // identical idea to your earlier helper: route get => iface+src, then link show => mac
    $route = @shell_exec("ip route get 1.1.1.1 2>/dev/null");
    if (!is_string($route) || trim($route) === "")
        return null;

    $iface = null;
    $ip = null;

    if (preg_match('/\bdev\s+([a-zA-Z0-9_.:-]+)\b/', $route, $m))
        $iface = $m[1];
    if (preg_match('/\bsrc\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b/', $route, $m))
        $ip = $m[1];

    if (!$iface || !$ip)
        return null;

    $link = @shell_exec("ip link show dev " . escapeshellarg($iface) . " 2>/dev/null");
    if (!is_string($link) || trim($link) === "")
        return null;

    $mac = null;
    if (preg_match('/\blink\/ether\s+([0-9a-fA-F:]{17})\b/', $link, $m))
        $mac = strtolower($m[1]);

    if (!$mac)
        return null;

    return ["ip" => $ip, "mac" => $mac];
}

/** Main function requested. */
function users_expell_intruders(): array
{
    global $Configuration;

    if (!isset($Configuration["InfosphereHand"]) || !is_string($Configuration["InfosphereHand"]) || trim($Configuration["InfosphereHand"]) === "")
        return ["ok" => false, "error" => "Configuration.InfosphereHand missing"];

    if (!function_exists("send_data"))
        return ["ok" => false, "error" => "send_data() missing"];

    $id = persoc_get_net_identity_for_exam();
    if ($id === null)
        return ["ok" => false, "error" => "cannot determine mac/ip"];

    // Ask IH
    $ans = send_data($Configuration["InfosphereHand"], [
        "command" => "is_exam",
        "mac" => $id["mac"],
        "ip" => $id["ip"],
    ]);

    if (!is_array($ans))
        return ["ok" => false, "error" => "is_exam: no response"];

    $exam = (bool)($ans["exam"] ?? false);
    $start_at = persoc_parse_start_at($ans["start_at"] ?? null);

    $sessions = persoc_list_graphical_sessions();

    // Optional pre-warning: starts in <5min, and only at seconds == 00
    $now = persoc_now();
    $sec = (int)date("s", $now);

    $warned = false;
    if ($start_at !== null)
    {
        $delta = $start_at - $now;
        if ($delta > 0 && $delta < 300 && $sec === 0)
        {
            // Message to all X/Wayland users
            // Keep simple & explicit
            $mins = (int)ceil($delta / 60);
            $when = date("H:i", $start_at);

            $msg =
                "⚠ EXAM imminent: début à " . $when . " (≈" . $mins . " min). "
              . "Veuillez sauvegarder votre trail, fermer votre session et quitter la salle.";

            // wall reads from stdin; avoid shell injection: use escapeshellarg
            @system("sh -c " . escapeshellarg("printf %s " . escapeshellarg($msg . "\n") . " | wall 2>/dev/null"), $rwall);
            $warned = true;
        }
    }

    $killed = [];
    foreach ($sessions as $s)
    {
        $user = (string)($s["user"] ?? "");
        $sid  = (string)($s["sid"] ?? "");

        if ($user === "") continue;

        $isExamUser = persoc_is_exam_account($user);

        if ($exam)
        {
            // exam mode: only a.b.exam allowed
            if (!$isExamUser)
            {
                persoc_kill_graphical_session($sid, $user);
                $killed[] = $user;
            }
        }
        else
        {
            // non-exam mode: exam accounts forbidden
            if ($isExamUser)
            {
                persoc_kill_graphical_session($sid, $user);
                $killed[] = $user;
            }
        }
    }

    return [
        "ok" => true,
        "exam" => $exam,
        "start_at" => $start_at,
        "warned" => $warned,
        "killed" => $killed,
        "graphical_sessions" => count($sessions),
    ];
}
