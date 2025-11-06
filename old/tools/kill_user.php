<?php

function kill_user(int $target_id,
		   string $target_name,
		   array $kill_area,
		   array $killer_manager)
{
    if (!isset($killer_manager["killed_user"][$target_name]) ||
	$killer_manager["killed_user"][$target_name] != ($killer_manager["time"] - 1))
    {
	system("pkill -u $target_id");
    }
    else
	system("pkill -u -9 $target_id");
    $killer_manager["killed_user"][$target_name] = $killer_manager["time"];
    unset($kill_area[$target_name]);
    return(true);
}
