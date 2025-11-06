<?php
// Jason Brillante "Damdoshi"
// Pentacle Technologie 2008-2025
// Hanged Bunny Studio 2014-2025
// EFRITS SAS 2025
//
// WorkSpy
// This software serves two purpose:
//  - Telling which user is connected so it can be logged into the scholarship website
//  and do work stats
//  - Keeping internet unavailable for users doing an exam

require_once (__FILE__."/tools/send_data.php");
require_once (__FILE__."/tools/hand_packet.php");
require_once (__FILE__."/tools/refresh_ip.php");
require_once (__FILE__."/tools/kill_unauthorized_sessions.php");
require_once (__FILE__."/tools/get_room.php");

// Reset nftables
system("sudo nft flush ruleset; nft add table inet filter");
require_once (__FILE__."/conf.php");
require_once (__FILE__."/logpacket.php");

$EXAM = false;

// Récupération des informations sur le poste.
$computer_name = explode(".", $packet["name"])[0];
$room_info = ["name" => get_room($computer_name, $nfs_server), "exam_only" => false];
$killer_manager = ["time" => 0, "killed_user" => []];

do
{
    // Récupération des élèves en examens
    $exam_stats = send_data($nfs_server, ["command" => "getexamstudents"]);
    
    $packet["ip"] = refresh_ip();
    $packet["users"] = explode("\n", trim(shell_exec("who | cut -d ' ' -f 1,2 | tr ' ' ';' | sort | uniq")));
    if (!isset($packet["users"]))
	continue;

    if (isset($exam_stats["users"]) && in_array($room_info["name"], $exam_stats["users"]))
	$room_info["exam_only"] = true;
    else
	$room_info["exam_only"] = false;

    // On parcoure les utilisateurs afin de trouver ceux en mode exam
    foreach ($packet["users"] as $usr)
    {
        $usr = explode(".", $usr);
	if (count($usr) == 1)
	    continue;
	$usr_part = explode(";", end($usr));
	$usr[count($usr) - 1] = $usr_part[0];
	$mode_connexion = $usr_part[1];
        
        if (kill_unauthorized_sessions($usr, $exam_stats, $packet["users"], $mode_connexion, $room_info, $nfs_server, $killer_manager))
            continue;

	    // Leur compte est forcement prenom.nom.exam
        if (count($usr) == 3 && substr($usr[2], 0, 4) == "exam")
	{	    
            $usr = shell_exec("id -u ".$usr[0].".".$usr[1].".exam");

	    $usr = str_replace("\n", "", $usr);
	    
            // On regarde si l'utilisateur est déjà dans la liste pour rejet
            $out = shell_exec("nft list ruleset | grep $usr");
            if (strlen($out) == 0 || str_contains($out, $usr) === false)
            {
            // Ce n'est pas le cas, on doit donc l'ajouter
		system("nft add chain inet filter output {type filter hook output ".
		       "priority filter \; policy accept \; }");

                system("nft add rule inet filter output meta skuid $usr ".
                       "ip daddr $ip_nfs tcp dport 111 accept");
                system("nft add rule inet filter output meta skuid $usr ".
                       "ip daddr $ip_nfs tcp dport 2049 accept");
                system("nft add rule inet filter output meta skuid $usr ".
                       "ip daddr $ip_nfs udp dport 111 accept");
                system("nft add rule inet filter output meta skuid $usr ".
                       "ip daddr $ip_nfs udp dport 2049 accept");

		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $ldap_server tcp dport 636 accept");
		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $ldap_server tcp dport 3269 accept");
		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $ldap_server udp dport 636 accept");
		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $ldap_server udp dport 3269 accept");

		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $net_server tcp dport 1337 accept");
		system("nft add rule inet filter output meta skuid $usr ".
		       "ip daddr $net_server tcp dport 1337 accept");
            
            if (system("nft add rule inet filter output meta skuid $usr reject") === false)
		kill_user(shell_exec("id -u ".$usr), $usr, $packet["users"], $killer_manager);
            }
        }
    }
    $killer_manager["time"] += 1;
    if ($killer_manager["time"] == 1000000)
	$killer_manager["time"] = 0;

    $packet["date"] = trim(date("d/m/Y H:i:s", time()));
    $packet["lock"] = file_exists("/tmp/block") && strncmp($mode_connexion, "tty", 3) == 0;
    send_data($nfs_server, $packet);

    system("sleep 5.0");
}
while (1);
exit(0);
