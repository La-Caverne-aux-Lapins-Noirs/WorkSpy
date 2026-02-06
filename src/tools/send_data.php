<?php
declare(strict_types=1);

/**
 * Build a packet file for Infosphere Hand:
 * - JSON (unicode unescaped) + "\v"
 * - split into chunks (2048)
 * - join with "\n"
 * - append "stop\v\n"
 * - write to a temp file with mode 0600
 *
 * @return string absolute path to the temp file
 */
function hand_packet(array $data, int $chunkSize = 2048, string $tmpDir = "/tmp"): string
{
    if ($chunkSize <= 0) {
        $chunkSize = 2048;
    }

    $payload = json_encode($data, JSON_UNESCAPED_UNICODE);
    if (!is_string($payload)) {
        // Extremely rare: json_encode failure
        $payload = "{}";
    }

    $payload .= "\v";

    $chunks = str_split($payload, $chunkSize);
    $chunks[] = "stop\v\n";
    $final = implode("\n", $chunks);

    $tmpDir = rtrim($tmpDir, "/");
    if ($tmpDir === "") {
        $tmpDir = "/tmp";
    }

    // Create a unique file path
    $ship = $tmpDir . "/.wsidle_msg_" . bin2hex(random_bytes(12));

    // Create file and set permissions early
    $oldUmask = umask(0077);
    $ok = @file_put_contents($ship, "");
    umask($oldUmask);

    if ($ok === false) {
        // fallback to /tmp if user provided a non-writable directory
        $ship = "/tmp/.wsidle_msg_" . bin2hex(random_bytes(12));
        $oldUmask = umask(0077);
        $ok = @file_put_contents($ship, "");
        umask($oldUmask);

        if ($ok === false) {
            // Last resort: let it fail loudly
            throw new RuntimeException("hand_packet: cannot create temp file");
        }
    }

    @chmod($ship, 0600);

    $ok2 = @file_put_contents($ship, $final);
    if ($ok2 === false) {
        @unlink($ship);
        throw new RuntimeException("hand_packet: cannot write temp file");
    }

    return $ship;
}

/**
 * Send data to Infosphere Hand over ssh, return decoded JSON from last line of stdout.
 *
 * Differences vs legacy:
 * - no shell pipeline, no inline rm (we unlink in PHP)
 * - safer argument escaping by using proc_open argv string built from fixed flags + escapeshellarg
 * - still returns json_decode(last_line, true)
 *
 * @return array|null decoded JSON object/array, or null if not decodable
 */
function send_data(
    string $host,
    array $data,
    string $sshUser = "infosphere_hand",
    int $port = 4422,
    string $identityFile = "/root/.ssh/ihk",
    string $remoteCommand = "infosphere_hand"
): ?array
{
    $ship = hand_packet($data);

    // Read packet to feed to ssh stdin
    $stdin = @file_get_contents($ship);
    @unlink($ship);

    if (!is_string($stdin)) {
        return null;
    }

    // SSH options (keep behaviour: no strict checking)
    // Using UserKnownHostsFile=/dev/null avoids writing to known_hosts.
    $args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-i", $identityFile,
        "-p", (string)$port,
        "-tt",
        $sshUser . "@" . $host,
        $remoteCommand,
    ];

    // Build a single command string with escapeshellarg
    $cmd = "";
    foreach ($args as $a) {
        $cmd .= ($cmd === "" ? "" : " ") . escapeshellarg($a);
    }

    $descriptorspec = [
        0 => ["pipe", "r"], // stdin
        1 => ["pipe", "w"], // stdout
        2 => ["pipe", "w"], // stderr (ignored, but drained)
    ];

    $proc = @proc_open($cmd, $descriptorspec, $pipes);
    if (!is_resource($proc)) {
        return null;
    }

    // Feed stdin then close
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);

    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // Drain stderr to avoid blocking
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $exitCode = proc_close($proc);

    if (!is_string($out) || trim($out) === "") {
        return null;
    }

    // Legacy: keep last non-empty line
    $lines = preg_split("/\r?\n/", $out);
    if (!is_array($lines)) {
        return null;
    }

    for ($i = count($lines) - 1; $i >= 0; --$i) {
        $line = trim((string)$lines[$i]);
        if ($line === "") continue;
        $decoded = json_decode($line, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $decoded;
        }
        // If last line is not JSON, legacy would return null-ish; we continue scanning backward
        // to be tolerant.
    }

    return null;
}
