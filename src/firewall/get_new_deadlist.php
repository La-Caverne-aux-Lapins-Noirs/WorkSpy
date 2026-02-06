<?php
declare(strict_types=1);

/**
 * Fetch the latest deadlist from Infosphere Hand, write it locally, and refresh nft rules via firewall_deadlist().
 *
 * No parameters:
 * - Uses $Configuration["InfosphereHand"] (mandatory)
 * - Uses $Configuration["Deadlist"] (mandatory)
 *
 * Expected IH response (tolerant):
 * - ["ok"=>true, "deadlist_csv"=>"...csv..."]
 *   OR
 * - ["ok"=>true, "deadlist"=>["1.2.3.4", "2001:db8::1", ...]]
 *
 * Returns:
 * - array with at least ["ok"=>bool]
 */
function get_new_deadlist(): array
{
    global $Configuration;

    $ih = (string)($Configuration["InfosphereHand"] ?? "");
    $dl = (string)($Configuration["Deadlist"] ?? "");

    if ($ih === "")
        return ["ok" => false, "error" => "Configuration.InfosphereHand missing"];
    if ($dl === "")
        return ["ok" => false, "error" => "Configuration.Deadlist missing"];

    // Ask Infosphere Hand
    $ans = send_data($ih, ["command" => "get_deadlist"]);
    if (!is_array($ans))
        return ["ok" => false, "error" => "invalid response from infosphere_hand"];

    if (($ans["ok"] ?? null) !== true && ($ans["result"] ?? null) !== "ok")
        return ["ok" => false, "error" => "infosphere_hand returned error", "response" => $ans];

    // Build CSV content
    $csv = null;

    if (isset($ans["deadlist_csv"]) && is_string($ans["deadlist_csv"]))
    {
        $csv = $ans["deadlist_csv"];
    }
    else if (isset($ans["deadlist"]) && is_array($ans["deadlist"]))
    {
        // Build minimal CSV: "host,reason"
        $lines = [];
        foreach ($ans["deadlist"] as $x)
        {
            if (!is_string($x)) continue;
            $x = trim($x);
            if ($x === "") continue;
            $lines[] = $x . ",remote";
        }
        $csv = implode("\n", $lines) . "\n";
    }

    if (!is_string($csv))
        return ["ok" => false, "error" => "missing deadlist content in IH response", "response" => $ans];

    // Atomic-ish write: write temp then rename
    $dir = dirname($dl);
    if (!is_dir($dir))
        @mkdir($dir, 0755, true);

    $tmp = $dl . ".tmp." . bin2hex(random_bytes(8));
    $ok = @file_put_contents($tmp, $csv);
    if ($ok === false)
        return ["ok" => false, "error" => "cannot write temp deadlist file: " . $tmp];

    @chmod($tmp, 0644);

    if (!@rename($tmp, $dl))
    {
        @unlink($tmp);
        return ["ok" => false, "error" => "cannot replace deadlist file: " . $dl];
    }

    // Refresh nft (your firewall_deadlist already does idempotent-ish work)
    firewall_deadlist($dl);

    return ["ok" => true, "path" => $dl];
}
