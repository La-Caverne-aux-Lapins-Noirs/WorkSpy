#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

// Load send_data + firewall_deadlist + get_new_deadlist
require_once $ROOT . "/src/tools/send_data.php";
require_once $ROOT . "/src/firewall/deadlist.php";
require_once $ROOT . "/src/firewall/get_new_deadlist.php";

assert_true(function_exists("get_new_deadlist"), "get_new_deadlist() not defined");

$tmp = mk_tmp_dir("persoc_unit_get_new_deadlist");
$bin = $tmp . "/bin";

$sshArgsLog = $tmp . "/ssh.args.log";
$sshStdin   = $tmp . "/ssh.stdin.dump";
$nftLog     = $tmp . "/nft.calls.log";

install_mock_ssh($bin, $sshArgsLog, $sshStdin, json_encode([
    "ok" => true,
    "deadlist_csv" => "1.2.3.4,ads\n2001:db8::1,ipv6\n"
], JSON_UNESCAPED_UNICODE));

install_mock_nft($bin, $nftLog);

global $Configuration;
$Configuration = [
    "InfosphereHand" => "ih.test",
    "Deadlist" => $tmp . "/deadlist.csv",
];

with_path_prefix($bin, function() {
    $res = get_new_deadlist();
    assert_true(is_array($res) && ($res["ok"] ?? false) === true, "get_new_deadlist should succeed");
});

// File should exist and contain our CSV
assert_true(file_exists($Configuration["Deadlist"]), "deadlist file was not created");
$csv = file_get_contents($Configuration["Deadlist"]);
assert_true(is_string($csv) && $csv !== "", "deadlist file is empty");
assert_contains($csv, "1.2.3.4", "deadlist file missing ipv4 entry");
assert_contains($csv, "2001:db8::1", "deadlist file missing ipv6 entry");

// firewall_deadlist should have hit nft
$calls = read_nft_calls($nftLog);
assert_true(count($calls) > 0, "No nft calls were recorded (firewall_deadlist probably not invoked)");

// sanity: sets should be mentioned
$joined = implode("\n", $calls);
assert_contains($joined, "deadlist_v4", "nft calls should reference deadlist_v4");
assert_contains($joined, "deadlist_v6", "nft calls should reference deadlist_v6");

// and our IPs should appear in add element calls (implementation-dependent but usually present)
assert_contains($joined, "1.2.3.4", "nft calls missing ipv4 element insertion");
assert_contains($joined, "2001:db8::1", "nft calls missing ipv6 element insertion");

rm_rf($tmp);
fwrite(STDOUT, "OK " . basename(__FILE__) . "\n");
exit(0);
