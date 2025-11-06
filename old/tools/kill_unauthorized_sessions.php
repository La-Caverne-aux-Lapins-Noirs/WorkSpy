<?php

function kill_unauthorized_sessions(array $user,
				    array $exam_stats,
				    array $user_pool,
				    string $mode_connexion,
				    array $room,
				    string $nfs_server,
				    array $killer_manager)
{
    $has_killed_user = false;
    $username = $user[0].".".$user[1];

    if (count($user) == 3 && substr($user[2], 0, 4) == "exam")
    {        
        $exam_username = $username.".exam";
        $user = shell_exec("id -u ".$exam_username);

        // On tue les sessions exam hors examens
        // Par contre ça va shutdown les sessions juste après le ramassage de Infosphere_hand mdr
	
	if (!isset($exam_stats["users"][$username]))
	    {
		$has_killed_user = kill_user($user, $exam_username, $user_pool, $killer_manager);
		send_data($nfs_server, ["command" => "addcustomlog",
				       "log" => "$exam_username has been killed, because ".
					      "there is no exam for now !"]);
	    }
	else if ($exam_stats["users"][$username] != $room["name"])
	    {
		$has_killed_user = kill_user($user, $exam_username, $user_pool, $killer_manager);
		send_data($nfs_server, ["command" => "addcustomlog",
				       "log" => "$exam_username has been killed, because ".
					      "$exam_username is not in the right room"]);
	    }

        // On tue les sessions exam qui ne sont pas en présentiels
        if (strncmp($mode_connexion, "tty", 3) != 0)
	    {
		$has_killed_user = kill_user($user, $exam_username, $user_pool, $killer_manager);
		send_data($nfs_server, ["command" => "addcustomlog",
				       "log" => "$exam_username has been killed, because ".
					      "exam cannot be in remote session"]);
	    }

        // On tue les sessions exam en double, 
        // Normalement il y le Xauthority qui n'est pas en lien symbolique
        // On regarde s'il l'utilisateur est déjà connecté et s'il ne l'est pas ailleurs
        if (isset($exam_stats["connected"][$exam_username])
	    && $exam_stats["connected"][$exam_username] != refresh_ip())
	{
            $has_killed_user = kill_user($user, $exam_username, $user_pool, $killer_manager);
	    send_data($nfs_server, ["command" => "addcustomlog",
				   "log" => "$exam_username has been killed because".
					  " $exam_username is already connected somewhere else !"]);
	}
    } // On tue toutes les sessions non exam présentiel dans une salle d'examen
/*    else if ($room["exam_only"] && strncmp($mode_connexion, "tty", 3) == 0)
    {
	$has_killed_user = kill_user(shell_exec("id -u ".$username), $username, $user_pool, $killer_manager);
	send_data($nfs_server, ["command" => "addcustomlog",
			       "log" => "$username has been killed because it's an exam only room"]);
    } */// On tue les sessions non exam d'utilisateur en exam
    else if (isset($exam_stats["users"][$username]))
    {
        $has_killed_user = kill_user(shell_exec("id -u ".$username), $username, $user_pool, $killer_manager);
	send_data($nfs_server, ["command" => "addcustomlog",
			       "log" => "$username has been killed because $username must be in exam"]);
    }
    return $has_killed_user;
}
