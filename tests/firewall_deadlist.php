#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

/*
 * This test assumes firewall_deadlist($csvPath) exists.
 * Adapt the require path below to wherever you put the function.
 *
 * Recommended: src/tools/firewall_deadlist.php
 */
$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

$maybe = [
    $ROOT . "/src/firewall/deadlist.php",
];
$loaded = false;
foreach ($maybe as $p) {
    if (file_exists($p)) {
        require_once $p;
        $loaded = true;
        break;
    }
}
assert_true($loaded, "Could not find firewall_deadlist.php (tried: " . implode(", ", $maybe) . ")");
assert_true(function_exists("firewall_deadlist"), "firewall_deadlist() not defined after include");

$tmp = mk_tmp_dir("persoc_unit_firewall_deadlist");
$bin = $tmp . "/bin";
$log = $tmp . "/nft.calls.log";

install_mock_nft($bin, $log);

// Deadlist: ONLY IPs to keep the test deterministic (no DNS dependency)
$csv = $tmp . "/deadlist.csv";
file_put_contents($csv, implode("\n", [
    "# comment line",
    "1.2.3.4,ads",
    "5.6.7.8,tracking",
    "2001:db8::1,ipv6-test",
    "",
]) . "\n");

with_path_prefix($bin, function() use ($csv) {
    $res = firewall_deadlist($csv);
    // Accept either bool or array return style; we just need it not to explode.
    assert_true($res !== null, "firewall_deadlist() returned null (unexpected)");
});

$calls = read_nft_calls($log);
assert_true(count($calls) > 0, "No nft calls were recorded (mock not used / PATH not applied)");

// Basic structure expected (table, chain, sets)
assert_true(nft_calls_has($calls, '/^nft\|add\|table\|inet\|filter\b/'), "Missing: nft add table inet filter");
assert_true(nft_calls_has($calls, '/^nft\|add\|chain\|inet\|filter\|output\b/'), "Missing: nft add chain inet filter output");

assert_true(nft_calls_has($calls, '/^nft\|add\|set\|inet\|filter\|deadlist_v4\b/'), "Missing: nft add set ... deadlist_v4");
assert_true(nft_calls_has($calls, '/^nft\|add\|set\|inet\|filter\|deadlist_v6\b/'), "Missing: nft add set ... deadlist_v6");

assert_true(nft_calls_has($calls, '/^nft\|flush\|set\|inet\|filter\|deadlist_v4\b/'), "Missing: nft flush set ... deadlist_v4");
assert_true(nft_calls_has($calls, '/^nft\|flush\|set\|inet\|filter\|deadlist_v6\b/'), "Missing: nft flush set ... deadlist_v6");

// Elements should be added (v4 and v6)
assert_true(nft_calls_has($calls, '/^nft\|add\|element\|inet\|filter\|deadlist_v4\b/'), "Missing: nft add element ... deadlist_v4");
assert_true(nft_calls_has($calls, '/^nft\|add\|element\|inet\|filter\|deadlist_v6\b/'), "Missing: nft add element ... deadlist_v6");

// Ensure our IPs appear somewhere in the add element calls
$joined = implode("\n", $calls);
assert_contains($joined, "1.2.3.4", "IPv4 1.2.3.4 not present in nft calls");
assert_contains($joined, "5.6.7.8", "IPv4 5.6.7.8 not present in nft calls");
assert_contains($joined, "2001:db8::1", "IPv6 2001:db8::1 not present in nft calls");

// Rules should be installed (either directly, or because list chain didn't match)
assert_true(nft_calls_has($calls, '/^nft\|add\|rule\|inet\|filter\|output\|ip\|daddr\|@deadlist_v4\|drop\b/'),
    "Missing: rule output ip daddr @deadlist_v4 drop");
assert_true(nft_calls_has($calls, '/^nft\|add\|rule\|inet\|filter\|output\|ip6\|daddr\|@deadlist_v6\|drop\b/'),
    "Missing: rule output ip6 daddr @deadlist_v6 drop");

rm_rf($tmp);
fwrite(STDOUT, "OK ".basename(__FILE__)."\n");
exit(0);

