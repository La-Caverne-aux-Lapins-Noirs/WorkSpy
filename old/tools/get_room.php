<?php

function get_room(string	$computer_name,
		  string	$nfs_server)
{
    $ret = send_data($nfs_server, [
	"command" => "getcomputerroom",
	"name" => $computer_name
    ]);
    if (isset($ret["result"]) && $ret["result"] == "ok")
	return $ret["message"];
    return "";
}
