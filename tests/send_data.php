#!/usr/bin/php
<?php
declare(strict_types=1);
date_default_timezone_set('UTC');

require_once __DIR__ . "/tools.php";

$ROOT = realpath(__DIR__ . "/..");
assert_true($ROOT !== false, "Cannot resolve project root");

$src = $ROOT . "/src/tools/send_data.php";
assert_true(file_exists($src), "Missing source file: " . $src);
require_once $src;

assert_true(function_exists("hand_packet"), "hand_packet() not defined");
assert_true(function_exists("send_data"), "send_data() not defined");

$tmp = mk_tmp_dir("persoc_unit_send_data");
$bin = $tmp . "/bin";
$argsLog = $tmp . "/ssh.args.log";
$stdinDump = $tmp . "/ssh.stdin.dump";

$expected = ["ok" => true, "answer" => 42];
$finalJson = json_encode($expected, JSON_UNESCAPED_UNICODE);
assert_true(is_string($finalJson), "json_encode failed in test");

install_mock_ssh($bin, $argsLog, $stdinDump, $finalJson);

$res = with_path_prefix($bin, function() {
    $data = ["command" => "ping", "x" => 1, "y" => "é"];
    return send_data("example.test", $data);
});

assert_true(is_array($res), "send_data() should return array");
assert_eq($res, $expected, "send_data() should decode last JSON line");

// Assert ssh was called
$args = file_exists($argsLog) ? file($argsLog, FILE_IGNORE_NEW_LINES) : [];
assert_true(is_array($args) && count($args) >= 1, "ssh mock was not invoked");

// Check that destination contains user@host and remote command
$joined = implode("\n", $args);
assert_contains($joined, "infosphere_hand@example.test", "ssh destination missing");
assert_contains($joined, "|infosphere_hand", "remote command missing");

// Assert stdin contains our packet structure (JSON + \v ... stop\v)
$stdin = file_exists($stdinDump) ? file_get_contents($stdinDump) : "";
assert_true(is_string($stdin) && $stdin !== "", "ssh stdin was not dumped");
assert_contains($stdin, "\"command\":\"ping\"", "stdin JSON missing command");
assert_contains($stdin, "\v", "stdin missing vertical-tab separator");
assert_contains($stdin, "stop\v", "stdin missing stop marker");

rm_rf($tmp);
fwrite(STDOUT, "OK ".basename(__FILE__)."\n");
exit(0);
