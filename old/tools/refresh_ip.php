<?php

function refresh_ip()
{
    $out = shell_exec("ip -o -4 addr list eno1 | tr -s ' ' | cut -d ' ' -f 4");
    $out = explode("/", $out)[0];
    return ($out);
}
