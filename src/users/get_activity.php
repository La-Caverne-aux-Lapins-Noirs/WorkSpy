<?php

function parse_duration($idle): int
{
    if ($idle == '.' || $idle == '')
        return (0);
    if (preg_match('/^([0-9]+)(\.[0-9]+)?s$/', $idle, $m))
	return ($m[1]);
    if (preg_match('/^([0-9]+):([0-9]+)?m?$/', $idle, $m))
	return ($m[1] * 60 + $m[2]);
    if (preg_match('/^([0-9]+):([0-9]+):([0-9]+)?$/', $idle, $m))
	return ($m[1] * 60 * 60 + $m[2] * 60 + $m[3]);
    if (preg_match('/^([0-9]+):([0-9]+):([0-9]+):([0-9]+)?$/', $idle, $m))
	return ($m[1] * 60 * 60 * 24 + $m[2] * 60 * 60 + $m[3] * 60 + $m[4]);
    return (0);
}

function is_user_lock($user)
{
    $lst = `ps -eo user,pid,etime,cmd | grep xtrlock-pam | grep $user | grep -v grep | tr -s ' '`;
    $lst = explode("\n", $lst);
    foreach ($lst as $l)
    {
	$l = explode(" ", $l);
	// On est strict sur la commande pour ne pas se tromper - "echo xtrlock-pam"
	if (count($l) >= 4 && preg_match('/^xtrlock-pam[ ]?/', $l[3]))
	    return (parse_duration($l[2]));
    }
    return (0);
}

function users_get_activity()
{
    $users = [];
    $lst = `PROCPS_USERLEN=32 w | tr -s ' '`;
    $lst = explode("\n", $lst);
    array_shift($lst);
    array_shift($lst);
    array_pop($lst);
    foreach ($lst as $l)
    {
	$l = explode(" ", $l);
	if (filter_var($l[2], FILTER_VALIDATE_IP))
	{
	    // SSH user
	    $users[] = [
		"username" => $l[0],
		"mode" => "ssh",
		"lock" => "false",
		"last_activity" => time() - parse_duration($l[4]),
	    ];
	}
	else
	{
	    // X user
	    $lock = is_user_lock($l[0]);
	    $users[] = [
		"username" => $l[0],
		"mode" => "x",
		"lock" => $lock != 0,
		"last_activity" => $lock != 0 ? time() - $lock : time()
	    ];
	}
    }
    return ($users);
}


