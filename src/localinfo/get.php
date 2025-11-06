<?php

function localinfo_get()
{
    $ip = `ip -o -4 addr show dev enp6s0 | tr -s ' ' | cut -d ' ' -f 4`
    $ip = explode("/", $ip)[0];
    return ([
	"mac" => `ip -o link show dev enp6s0 | tr -s ' ' | cut -d ' ' -f 17`,
	"type" => `uname -m`
	"name" => `hostname`,
	"ip" => $ip
    ]);
}
