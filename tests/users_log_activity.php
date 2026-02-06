#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

// Load send_data (for ssh mock) + persoc function
require_once $ROOT . "/src/tools/send_data.php";
require_once $ROOT . "/src/users/log_activity.php";

assert_true(function_exists("users_log_activity"), "users_log_activity() not defined");

$tmp = mk_tmp_dir("persoc_unit_log_activity");
$bin = $tmp . "/bin";
$argsLog = $tmp . "/ssh.args.log";
$stdinDump = $tmp . "/ssh.stdin.dump";

global $Configuration;
$Configuration = [
    "InfosphereHand" => "ih.test",
];

// Mock ssh: returns JSON as last line
$expected = ["ok" => true, "msg" => "stored"];
$finalJson = json_encode($expected, JSON_UNESCAPED_UNICODE);
assert_true(is_string($finalJson), "json_encode failed in test");

install_mock_ssh($bin, $argsLog, $stdinDump, $finalJson);

// Mock hostname
install_mock_cmd($bin, "hostname", <<<'SH'
#!/bin/sh
echo "pc01"
SH);

// Mock ip (route get + link show)
install_mock_cmd($bin, "ip", <<<'SH'
#!/bin/sh
if [ "$1" = "route" ] && [ "$2" = "get" ]; then
  # Typical ip route get output
  echo "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0"
  exit 0
fi

if [ "$1" = "link" ] && [ "$2" = "show" ] && [ "$3" = "dev" ]; then
  echo "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
  echo "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
  exit 0
fi

exit 1
SH);

// Mock w (2 header lines + 2 user lines)
install_mock_cmd($bin, "w", <<<'SH'
#!/bin/sh
echo " 17:00:00 up 1 day,  2 users,  load average: 0.00, 0.00, 0.00"
echo "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
# X user: column[2] not an IP, idle '.' (=> now)
echo "alice    tty7     :0               16:00   .      0.01s  0.01s -"
# SSH user: column[2] is an IP, idle "0:30" (=> 30 seconds)
echo "bob      pts/0    192.168.1.70     16:30   0:30   0.01s  0.01s -"
SH);

// Mock ps for lock detection of alice (xtrlock-pam running for 00:05 => 5 seconds)
install_mock_cmd($bin, "ps", <<<'SH'
#!/bin/sh
# supports: ps -eo user,pid,etime,cmd
echo "alice  123  00:05  xtrlock-pam"
exit 0
SH);

$res = with_path_prefix($bin, function() {
    return users_log_activity();
});

assert_true(is_array($res), "users_log_activity should return array");
assert_eq($res, $expected, "decoded response mismatch");

// Check ssh destination
$args = file_exists($argsLog) ? file($argsLog, FILE_IGNORE_NEW_LINES) : [];
assert_true(is_array($args) && count($args) >= 1, "ssh mock not invoked");

$joinedArgs = implode("\n", $args);
assert_contains($joinedArgs, "infosphere_hand@ih.test", "ssh destination missing");

// Verify stdin packet contains required keys for IH log_activity
$stdin = file_exists($stdinDump) ? file_get_contents($stdinDump) : "";
assert_true(is_string($stdin) && $stdin !== "", "ssh stdin not dumped");

assert_contains($stdin, "\"command\":\"log_activity\"", "packet missing command");
assert_contains($stdin, "\"mac\":\"aa:bb:cc:dd:ee:ff\"", "packet missing mac");
assert_contains($stdin, "\"name\":\"pc01\"", "packet missing name");
assert_contains($stdin, "\"ip\":\"192.168.1.50\"", "packet missing ip");
assert_contains($stdin, "\"type\":", "packet missing type");
assert_contains($stdin, "\"users\":", "packet missing users");
assert_contains($stdin, "\"username\":\"alice\"", "packet missing alice");
assert_contains($stdin, "\"mode\":\"x\"", "packet missing x mode");
assert_contains($stdin, "\"lock\":true", "packet missing lock true");
assert_contains($stdin, "\"username\":\"bob\"", "packet missing bob");
assert_contains($stdin, "\"mode\":\"ssh\"", "packet missing ssh mode");
assert_contains($stdin, "stop\v", "packet missing stop marker");

rm_rf($tmp);
fwrite(STDOUT, "OK ".basename(__FILE__)."\n");
exit(0);
