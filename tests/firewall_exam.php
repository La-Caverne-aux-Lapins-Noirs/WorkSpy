#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

/*
 * Adapter ce require à l’endroit où tu vas ranger firewall_exam().
 * (Je ne connais pas encore ton chemin exact pour ce nouveau fichier.)
 */
$maybe = [
    $ROOT . "/src/firewall/exam.php",
];
$loaded = false;
foreach ($maybe as $p) {
    if (file_exists($p)) {
        require_once $p;
        $loaded = true;
        break;
    }
}
assert_true($loaded, "Could not find firewall_exam source (tried: " . implode(", ", $maybe) . ")");
assert_true(function_exists("firewall_exam"), "firewall_exam() not defined after include");

// Provide configuration: allowed endpoints must pass
global $Configuration;
$Configuration = [
    "NFS" => ["10.10.0.10"],      // already IP => deterministic
    "LDAP" => ["10.10.0.20"],
    "CUSTOM" => ["10.10.0.30"],
];

$tmp = mk_tmp_dir("persoc_unit_firewall_exam");
$bin = $tmp . "/bin";
$log = $tmp . "/nft.calls.log";
install_mock_nft($bin, $log);

// Mock systemd sessions:
// - session 2: alice is wayland (graphical) => should be filtered
// - session 3: bob is tty => should not be in exam_uids
install_mock_loginctl($bin, [
    "2" => ["Name" => "alice", "Type" => "wayland", "Class" => "user"],
    "3" => ["Name" => "bob",   "Type" => "tty",     "Class" => "user"],
]);
$out = with_path_prefix($bin, fn() => shell_exec("loginctl show-session 2 -p Name -p Type -p Class"));
assert_contains((string)$out, "Type=wayland", "mock loginctl should return Type=wayland for session 2");


// Ensure UID resolution is deterministic even without real system users.
install_mock_id($bin, [
    "alice" => 1001,
    "bob"   => 1002,
]);

with_path_prefix($bin, function() {
    $res = firewall_exam(true);
    assert_true(is_array($res), "firewall_exam(true) should return array");
    assert_eq($res["mode"] ?? "", "exam", "mode should be exam");
    assert_eq($res["graphical_users"] ?? -1, 1, "graphical_users should be 1 (alice only)");
    assert_eq($res["exam_uids"] ?? -1, 1, "exam_uids should be 1 (alice only)");
});

$calls = read_nft_calls($log);
assert_true(count($calls) > 0, "No nft calls were recorded");

$joined = implode("\n", $calls);

// We expect alice UID 1001 to be in exam_uids add element
assert_contains($joined, "exam_uids", "exam_uids set never referenced");
assert_contains($joined, "1001", "UID 1001 (alice) not present in nft calls");
// and bob should NOT appear as UID 1002 in exam_uids element
assert_true(strpos($joined, "|1002") === false, "UID 1002 (bob) should not be present (not graphical)");

// Allowed IPs should be inserted
assert_contains($joined, "10.10.0.10", "NFS allowed IP missing");
assert_contains($joined, "10.10.0.20", "LDAP allowed IP missing");
assert_contains($joined, "10.10.0.30", "CUSTOM allowed IP missing");

// Ensure the drop rule for exam users is installed
assert_true(nft_calls_has($calls, '/^nft\|add\|rule\|inet\|filter\|exam_out\|meta\|skuid\|@exam_uids\|drop\b/'),
    "Missing: drop rule in exam_out");

rm_rf($tmp);
fwrite(STDOUT, "OK ".basename(__FILE__)."\n");
exit(0);
