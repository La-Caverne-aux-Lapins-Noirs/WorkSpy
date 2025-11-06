<?php

function persoc_log($str)
{
    global $Machine;
    
    file_put_contents("/var/log/persoc.log", $str, FILE_APPEND);
    send_data(["command" => "persoclog", "machine" => $Machine["hostname"], "log" => "$str"]);
}

