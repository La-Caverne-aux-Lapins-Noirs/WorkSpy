<?php
declare(strict_types=1);

// Jason Brillante "Damdoshi"
// Pentacle Technologie 2008-2025
// Hanged Bunny Studio 2014-2025
// EFRITS SAS 2025
//
// Persoc (daemon bootstrap + main loop)

require_once (__DIR__."/firewall/deadlist.php");
require_once (__DIR__."/firewall/exam.php");
require_once (__DIR__."/firewall/reset.php");
require_once (__DIR__."/tools/send_data.php");
require_once (__DIR__."/users/expell_intruders.php");
require_once (__DIR__."/users/log_activity.php");

// -----------------------------------------------------------------------------
// Logging
// -----------------------------------------------------------------------------

function persoc_log(string $msg): void
{
    fwrite(STDERR, "[" . date("Y-m-d H:i:s") . "] persoc: " . $msg . "\n");
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

$Configuration = null;

function load_configuration(string $conf_file = ""): array
{
    if ($conf_file === "")
    {
        if (file_exists("./persoc.dab"))
            $conf_file = "./persoc.dab";
        else if (isset($_SERVER["HOME"]) && file_exists($_SERVER["HOME"] . "/persoc.dab"))
            $conf_file = $_SERVER["HOME"] . "/persoc.dab";
        else
            $conf_file = "/etc/persoc/persoc.dab /etc/persoc/confs.d/*";
    }

    $conf_file = escapeshellarg($conf_file);
    $raw = shell_exec("mergeconf -i " . $conf_file . " -of .json --resolve 2>/dev/null");
    $conf = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($conf))
        throw new RuntimeException("cannot load configuration via mergeconf");

    // Mandatory fields
    foreach (["InfosphereHand", "NFS", "LDAP"] as $k)
    {
        if (!array_key_exists($k, $conf))
            throw new RuntimeException("missing configuration field: " . $k);
    }
    if (!is_string($conf["InfosphereHand"]) || trim($conf["InfosphereHand"]) === "")
        throw new RuntimeException("InfosphereHand must be a non-empty string");

    // Normalize allowlists (NFS/LDAP mandatory, CUSTOM optional)
    foreach (["NFS", "LDAP", "CUSTOM"] as $k)
    {
        if (!array_key_exists($k, $conf))
        {
            $conf[$k] = [];
            continue;
        }

        if (is_string($conf[$k]))
            $conf[$k] = [trim($conf[$k])];
        if (!is_array($conf[$k]))
            throw new RuntimeException("$k must be string or array");

        $out = [];
        foreach ($conf[$k] as $v)
        {
            if (!is_string($v))
                continue;
            $v = trim($v);
            if ($v !== "")
                $out[] = $v;
        }
        $conf[$k] = array_values(array_unique($out));

        if (($k === "NFS" || $k === "LDAP") && count($conf[$k]) === 0)
            throw new RuntimeException("$k must not be empty");
    }

    // Optional: deadlist file
    if (!isset($conf["Deadlist"]) || !is_string($conf["Deadlist"]) || trim($conf["Deadlist"]) === "")
        $conf["Deadlist"] = "/etc/persoc/deadlist.csv";

    // Intervals defaults are centralized here
    if (!isset($conf["Intervals"]) || !is_array($conf["Intervals"]))
        $conf["Intervals"] = [];

    if (!isset($conf["Intervals"]["Tick"]))      $conf["Intervals"]["Tick"] = 1;
    if (!isset($conf["Intervals"]["Activity"]))  $conf["Intervals"]["Activity"] = 5;
    if (!isset($conf["Intervals"]["Intruders"])) $conf["Intervals"]["Intruders"] = 5;
    if (!isset($conf["Intervals"]["Deadlist"]))  $conf["Intervals"]["Deadlist"] = 0;

    $conf["Intervals"]["Tick"]      = max(1, (int)$conf["Intervals"]["Tick"]);
    $conf["Intervals"]["Activity"]  = max(1, (int)$conf["Intervals"]["Activity"]);
    $conf["Intervals"]["Intruders"] = max(1, (int)$conf["Intervals"]["Intruders"]);
    $conf["Intervals"]["Deadlist"]  = max(0, (int)$conf["Intervals"]["Deadlist"]);

    return $conf;
}

// -----------------------------------------------------------------------------
// Signals
// -----------------------------------------------------------------------------

$GLOBALS["PERSOC_STOP"] = false;

function persoc_install_signal_handlers(): void
{
    if (!function_exists("pcntl_signal"))
        return;

    pcntl_signal(SIGTERM, function() { $GLOBALS["PERSOC_STOP"] = true; });
    pcntl_signal(SIGINT,  function() { $GLOBALS["PERSOC_STOP"] = true; });
}

function persoc_pump_signals(): void
{
    if (function_exists("pcntl_signal_dispatch"))
        pcntl_signal_dispatch();
}

function persoc_should_stop(): bool
{
    return (bool)$GLOBALS["PERSOC_STOP"];
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

try
{
    $Configuration = load_configuration();
    $GLOBALS["Configuration"] = $Configuration; // required by modules

    persoc_install_signal_handlers();

    // Startup: reset + deadlist
    persoc_log("startup: firewall_reset()");
    firewall_reset();

    persoc_log("startup: firewall_deadlist()");
    firewall_deadlist($Configuration["Deadlist"]);

    $tick = (int)$Configuration["Intervals"]["Tick"];
    $activityEvery = (int)$Configuration["Intervals"]["Activity"];
    $intrudersEvery = (int)$Configuration["Intervals"]["Intruders"];
    $deadlistEvery = (int)$Configuration["Intervals"]["Deadlist"];

    persoc_log("running: tick={$tick}s activity={$activityEvery}s intruders={$intrudersEvery}s deadlist={$deadlistEvery}s");

    $nextActivity = 0;
    $nextIntruders = 0;
    $nextDeadlist = 0;

    while (!persoc_should_stop())
    {
        persoc_pump_signals();
        $now = time();

        if ($deadlistEvery > 0 && $now >= $nextDeadlist)
        {
            $nextDeadlist = $now + $deadlistEvery;
            firewall_deadlist($Configuration["Deadlist"]);
        }

        if ($now >= $nextActivity)
        {
            $nextActivity = $now + $activityEvery;
            persoc_send_log_activity();
        }

        if ($now >= $nextIntruders)
        {
            $nextIntruders = $now + $intrudersEvery;

            // Ask IH (via users_expell_intruders) and apply exam firewall accordingly
            $r = users_expell_intruders();
            $exam = is_array($r) ? (bool)($r["exam"] ?? false) : false;
            firewall_exam($exam);
        }

        sleep($tick);
    }

    persoc_log("stopping.");
    exit(0);
}
catch (Throwable $e)
{
    persoc_log("FATAL: " . $e->getMessage());
    exit(2);
}
