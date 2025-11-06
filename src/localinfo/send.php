<?php

function localinfo_send($local_info, $users)
{
    send_data(array_merge($info, [
	"command" => "log",
	"users" => $users
    ]));
}

