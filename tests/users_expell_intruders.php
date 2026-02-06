#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

// Need send_data (ssh mocked) + users_expell_intruders
require_once $ROOT . "/src/tools/send_data.php";
require_once $ROOT . "/src/users/expell_intruders.php";

assert_true(function_exists("users_expell_intruders"), "users_expell_intruders() not defined");

$tmp = mk_tmp_dir("persoc_unit_users_expell");
$bin = $tmp . "/bin";

$sshArgsLog  = $tmp . "/ssh.args.log";
$sshStdin    = $tmp . "/ssh.stdin.dump";
$loginctlLog = $tmp . "/loginctl.log";
$wallLog     = $tmp . "/wall.log";
$wallStdin   = $tmp . "/wall.stdin.dump";

// Network identity for IH is_exam (mac needed)
install_mock_ip_basic($bin, "eth0", "192.168.1.50", "aa:bb:cc:dd:ee:ff");

// Graphical sessions: alice (normal), john.doe.exam (exam account)
install_mock_loginctl_with_terminate($bin, $loginctlLog, [
    "10" => ["Name" => "alice",        "Type" => "wayland", "Class" => "user"],
    "11" => ["Name" => "john.doe.exam","Type" => "x11",     "Class" => "user"],
]);

install_mock_wall($bin, $wallLog, $wallStdin);

global $Configuration;
$Configuration = [
    "InfosphereHand" => "ih.test",
];

// ---- Scenario 1: exam = true, start_at in 4 min, now seconds == 00 => wall + expel alice ----
$now = 1700000000 - (1700000000 % 60); // fixed epoch, ends with ...00 seconds? (it does)
putenv("PERSOC_NOW=" . $now);

$resp1 = json_encode([
    "result" => "ok",
    "exam" => true,
    "start_at" => $now + 240
], JSON_UNESCAPED_UNICODE);
assert_true(is_string($resp1), "json_encode resp1 failed");

install_mock_ssh($bin, $sshArgsLog, $sshStdin, $resp1);

with_path_prefix($bin, function() {
    $res = users_expell_intruders();
    assert_true(is_array($res) && ($res["ok"] ?? false) === true, "users_expell_intruders failed (scenario 1)");
    assert_true(($res["exam"] ?? null) === true, "scenario 1 should be exam=true");
    // alice should be killed, exam account should remain
    $k = $res["killed"] ?? [];
    assert_true(is_array($k), "killed must be array");
    assert_true(in_array("alice", $k, true), "alice must be expelled in exam mode");
    assert_true(!in_array("john.doe.exam", $k, true), "exam user must not be expelled in exam mode");
    assert_true(($res["warned"] ?? false) === true, "should warn via wall when start_at < 5min and seconds==00");
});

// Check loginctl terminate-session called for sid 10 (alice)
$lcalls = file_exists($loginctlLog) ? file($loginctlLog, FILE_IGNORE_NEW_LINES) : [];
$joined = is_array($lcalls) ? implode("\n", $lcalls) : "";
assert_contains($joined, "terminate-session|10", "should terminate session 10 (alice) in scenario 1");
assert_true(strpos($joined, "terminate-session|11") === false, "must NOT terminate exam session 11 in scenario 1");

// Check wall was called and message dumped
$wlog = file_exists($wallLog) ? file_get_contents($wallLog) : "";
assert_true(is_string($wlog) && trim($wlog) !== "", "wall should be invoked in scenario 1");
$wmsg = file_exists($wallStdin) ? file_get_contents($wallStdin) : "";
assert_true(is_string($wmsg) && strpos($wmsg, "EXAM imminent") !== false, "wall message should mention exam imminent");

// ---- Scenario 2: exam = false => expel john.doe.exam, no wall requirement ----
// Reset logs
@unlink($loginctlLog);
@unlink($wallLog);
@unlink($wallStdin);

$resp2 = json_encode([
    "result" => "ok",
    "exam" => false
], JSON_UNESCAPED_UNICODE);
assert_true(is_string($resp2), "json_encode resp2 failed");

install_mock_ssh($bin, $sshArgsLog, $sshStdin, $resp2);

with_path_prefix($bin, function() {
    $res = users_expell_intruders();
    assert_true(is_array($res) && ($res["ok"] ?? false) === true, "users_expell_intruders failed (scenario 2)");
    assert_true(($res["exam"] ?? null) === false, "scenario 2 should be exam=false");
    $k = $res["killed"] ?? [];
    assert_true(in_array("john.doe.exam", $k, true), "exam user must be expelled when not in exam mode");
    assert_true(!in_array("alice", $k, true), "normal user must not be expelled when not in exam mode");
});

// loginctl terminate-session must target sid 11 now
$lcalls2 = file_exists($loginctlLog) ? file($loginctlLog, FILE_IGNORE_NEW_LINES) : [];
$joined2 = is_array($lcalls2) ? implode("\n", $lcalls2) : "";
assert_contains($joined2, "terminate-session|11", "should terminate session 11 (john.doe.exam) in scenario 2");
assert_true(strpos($joined2, "terminate-session|10") === false, "must NOT terminate alice session 10 in scenario 2");

// wall should not be invoked
$wlog2 = file_exists($wallLog) ? file_get_contents($wallLog) : "";
assert_true(!is_string($wlog2) || trim($wlog2) === "", "wall should not be invoked in scenario 2");

rm_rf($tmp);
fwrite(STDOUT, "OK ".basename(__FILE__)."\n");
exit(0);
