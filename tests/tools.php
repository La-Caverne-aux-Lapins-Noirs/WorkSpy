<?php
declare(strict_types=1);

/*
 * Common test helpers for Persoc / Infosphere-Hand style scripts.
 * Put ALL test tools here as requested.
 */

function assert_true(bool $cond, string $msg): void {
    if (!$cond) {
        fwrite(STDERR, "ASSERT FAIL: $msg\n");
        exit(1);
    }
}

function assert_eq(mixed $a, mixed $b, string $msg): void {
    if ($a !== $b) {
        fwrite(STDERR, "ASSERT FAIL: $msg\nGot: " . var_export($a, true) . "\nExp: " . var_export($b, true) . "\n");
        exit(1);
    }
}

function assert_contains(string $haystack, string $needle, string $msg): void {
    if (strpos($haystack, $needle) === false) {
        fwrite(STDERR, "ASSERT FAIL: $msg\nMissing: " . var_export($needle, true) . "\nIn: " . $haystack . "\n");
        exit(1);
    }
}

function mk_tmp_dir(string $prefix): string {
    $base = rtrim(sys_get_temp_dir(), '/');
    $dir  = $base . '/' . $prefix . '_' . getmypid() . '_' . bin2hex(random_bytes(6));
    @mkdir($dir, 0755, true);
    return $dir;
}

function rm_rf(string $path): void {
    if (!file_exists($path)) return;
    if (is_file($path) || is_link($path)) { @unlink($path); return; }

    $items = scandir($path);
    if (!$items) { @rmdir($path); return; }

    foreach ($items as $it) {
        if ($it === '.' || $it === '..') continue;
        rm_rf($path . '/' . $it);
    }
    @rmdir($path);
}

function put_exe(string $path, string $content): void {
    file_put_contents($path, $content);
    chmod($path, 0755);
}

/**
 * Create a fake `nft` executable that records every invocation into $logFile.
 *
 * Notes:
 * - Works with `system("nft ...; nft ...")` because /bin/sh resolves nft via PATH.
 * - For `nft list chain ...`, we output nothing (so grep -q fails and the code adds rules).
 */
function install_mock_nft(string $binDir, string $logFile): void
{
    @mkdir($binDir, 0755, true);

    $sh = <<<'SH'
#!/bin/sh
LOGFILE="%LOGFILE%"

# Record the command in a stable-ish way.
# We record argv as a single line: nft|arg1|arg2|...
out="nft"
for a in "$@"; do
  out="$out|$a"
done
echo "$out" >> "$LOGFILE"

# Provide empty output for list operations by default.
# (Your code uses grep -q on "nft list chain ...", so empty => rule will be added.)
exit 0
SH;

    $sh = str_replace("%LOGFILE%", addslashes($logFile), $sh);
    put_exe($binDir . "/nft", $sh);
}

/**
 * Run a callable with PATH prefixed by $binDir (restored afterwards).
 */
function with_path_prefix(string $binDir, callable $fn): mixed
{
    $old = getenv("PATH") ?: "";
    putenv("PATH=" . $binDir . ":" . $old);
    try {
        return $fn();
    } finally {
        putenv("PATH=" . $old);
    }
}

/**
 * Read mock nft log lines (each line is "nft|arg|arg|...").
 */
function read_nft_calls(string $logFile): array
{
    if (!file_exists($logFile)) return [];
    $raw = file($logFile, FILE_IGNORE_NEW_LINES);
    if ($raw === false) return [];
    return array_values(array_filter(array_map('trim', $raw), fn($l) => $l !== ""));
}

/**
 * Find whether an nft call matching $pattern exists.
 * $pattern is a regex applied to the raw log line.
 */
function nft_calls_has(array $calls, string $pattern): bool
{
    foreach ($calls as $c) {
        if (preg_match($pattern, $c)) return true;
    }
    return false;
}

function install_mock_loginctl(string $binDir, array $sessions): void
{
    @mkdir($binDir, 0755, true);

    $db = [];
    foreach ($sessions as $sid => $props) {
        $db[(string)$sid] = [
            "Name"  => (string)($props["Name"]  ?? ""),
            "Type"  => (string)($props["Type"]  ?? ""),
            "Class" => (string)($props["Class"] ?? ""),
        ];
    }

    $json = json_encode($db, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) $json = "{}";

    // Safe embed into single quotes in sh
    $jsonEsc = str_replace("'", "'\"'\"'", $json);

    $sh = <<<SH
#!/bin/sh
DB='$jsonEsc'

cmd="\$1"
shift

if [ "\$cmd" = "list-sessions" ]; then
  # loginctl list-sessions --no-legend
  MOCK_LOGINCTL_DB="\$DB" php -r '
    \$db = json_decode(getenv("MOCK_LOGINCTL_DB"), true) ?: [];
    foreach (\$db as \$sid => \$p) {
      \$name = \$p["Name"] ?? "unknown";
      echo \$sid . " " . \$name . " seat0 tty0\\n";
    }
  '
  exit 0
fi

if [ "\$cmd" = "show-session" ]; then
  sid="\$1"
  shift
  MOCK_LOGINCTL_DB="\$DB" MOCK_LOGINCTL_SID="\$sid" php -r '
    \$db  = json_decode(getenv("MOCK_LOGINCTL_DB"), true) ?: [];
    \$sid = getenv("MOCK_LOGINCTL_SID");
    \$p = \$db[\$sid] ?? [];
    foreach (["Name","Type","Class"] as \$k) {
      \$v = \$p[\$k] ?? "";
      echo \$k . "=" . \$v . "\\n";
    }
  '
  exit 0
fi

# Ignore other subcommands
exit 0
SH;

    put_exe($binDir . "/loginctl", $sh);
}

function install_mock_id(string $binDir, array $map): void
{
    @mkdir($binDir, 0755, true);

    $json = json_encode($map, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) $json = "{}";

    // Safe embed into single quotes in sh
    $jsonEsc = str_replace("'", "'\"'\"'", $json);

    $sh = <<<'SH'
#!/bin/sh
# supports only: id -u <user>
if [ "$1" != "-u" ]; then
  exit 1
fi
user="$2"
MOCK_ID_USER="$user" php -r '
  $m = json_decode(getenv("MOCK_ID_DB"), true) ?: [];
  $u = getenv("MOCK_ID_USER");
  if (!array_key_exists($u, $m)) { exit(1); }
  echo (int)$m[$u];
'
exit 0
SH;

    $wrapper = <<<SH
#!/bin/sh
export MOCK_ID_DB='$jsonEsc'
exec "%REAL%" "\$@"
SH;

    $real = $binDir . "/.id.real";
    $wrap = $binDir . "/id";

    $wrapper = str_replace("%REAL%", $real, $wrapper);

    put_exe($real, $sh);
    put_exe($wrap, $wrapper);
}

/**
 * Mock `ssh` executable:
 * - records argv to $argsLogFile
 * - writes stdin to $stdinDumpFile
 * - prints a multi-line stdout ending with a JSON line (configurable)
 */
function install_mock_ssh(string $binDir, string $argsLogFile, string $stdinDumpFile, string $finalJsonLine): void
{
    @mkdir($binDir, 0755, true);

    // escape single quotes for embedding in sh single quotes
    $finalJsonEsc = str_replace("'", "'\"'\"'", $finalJsonLine);
    $argsLogEsc   = str_replace("'", "'\"'\"'", $argsLogFile);
    $stdinEsc     = str_replace("'", "'\"'\"'", $stdinDumpFile);

    $sh = <<<SH
#!/bin/sh
# Record argv (one line)
out="ssh"
for a in "\$@"; do
  out="\$out|\$a"
done
echo "\$out" >> '$argsLogEsc'

# Dump stdin
cat > '$stdinEsc'

# Simulate some noisy output + final JSON line
echo "hello"
echo "world"
printf '%s\n' '$finalJsonEsc'
exit 0
SH;

    put_exe($binDir . "/ssh", $sh);
}

function install_mock_cmd(string $binDir, string $name, string $script): void
{
    @mkdir($binDir, 0755, true);
    put_exe($binDir . "/" . $name, $script);
}

function install_mock_loginctl_with_terminate(string $binDir, string $logFile, array $sessions): void
{
    @mkdir($binDir, 0755, true);

    $db = [];
    foreach ($sessions as $sid => $props) {
        $db[(string)$sid] = [
            "Name"  => (string)($props["Name"]  ?? ""),
            "Type"  => (string)($props["Type"]  ?? ""),
            "Class" => (string)($props["Class"] ?? ""),
        ];
    }

    $json = json_encode($db, JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) $json = "{}";

    $logEsc  = str_replace("'", "'\"'\"'", $logFile);
    $jsonEsc = str_replace("'", "'\"'\"'", $json);

    $sh = <<<SH
#!/bin/sh
DB='$jsonEsc'
LOGFILE='$logEsc'

cmd="\$1"
shift

if [ "\$cmd" = "list-sessions" ]; then
  # loginctl list-sessions --no-legend
  MOCK_LOGINCTL_DB="\$DB" php -r '
    \$db = json_decode(getenv("MOCK_LOGINCTL_DB"), true) ?: [];
    foreach (\$db as \$sid => \$p) {
      \$name = \$p["Name"] ?? "unknown";
      echo \$sid . " " . \$name . " seat0 tty0\\n";
    }
  '
  exit 0
fi

if [ "\$cmd" = "show-session" ]; then
  sid="\$1"
  shift
  MOCK_LOGINCTL_DB="\$DB" MOCK_SID="\$sid" php -r '
    \$db = json_decode(getenv("MOCK_LOGINCTL_DB"), true) ?: [];
    \$sid = getenv("MOCK_SID");
    \$p = \$db[\$sid] ?? [];
    foreach (["Name","Type","Class"] as \$k) {
      \$v = \$p[\$k] ?? "";
      echo \$k . "=" . \$v . "\\n";
    }
  '
  exit 0
fi

if [ "\$cmd" = "terminate-session" ]; then
  sid="\$1"
  echo "loginctl|terminate-session|\$sid" >> "\$LOGFILE"
  exit 0
fi

exit 0
SH;

    put_exe($binDir . "/loginctl", $sh);
}

/** Mock wall: records invocations + stdin content */
function install_mock_wall(string $binDir, string $logFile, string $stdinDumpFile): void
{
    @mkdir($binDir, 0755, true);

    $logEsc   = str_replace("'", "'\"'\"'", $logFile);
    $stdinEsc = str_replace("'", "'\"'\"'", $stdinDumpFile);

    $sh = <<<SH
#!/bin/sh
# record args
out="wall"
for a in "\$@"; do
  out="\$out|\$a"
done
echo "\$out" >> '$logEsc'
# dump stdin
cat > '$stdinEsc'
exit 0
SH;

    put_exe($binDir . "/wall", $sh);
}

/** Mock ip: route get + link show (v4 + mac) */
function install_mock_ip_basic(string $binDir, string $iface, string $ip, string $mac): void
{
    @mkdir($binDir, 0755, true);

    $ifaceEsc = str_replace("'", "'\"'\"'", $iface);
    $ipEsc    = str_replace("'", "'\"'\"'", $ip);
    $macEsc   = str_replace("'", "'\"'\"'", $mac);

    $sh = <<<SH
#!/bin/sh
if [ "\$1" = "route" ] && [ "\$2" = "get" ]; then
  echo "1.1.1.1 via 192.168.1.1 dev $ifaceEsc src $ipEsc uid 0"
  exit 0
fi
if [ "\$1" = "link" ] && [ "\$2" = "show" ] && [ "\$3" = "dev" ]; then
  echo "2: $ifaceEsc: <UP> mtu 1500"
  echo "    link/ether $macEsc brd ff:ff:ff:ff:ff:ff"
  exit 0
fi
exit 1
SH;

    put_exe($binDir . "/ip", $sh);
}
