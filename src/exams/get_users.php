<?php

function exam_get_users()
{
    global $Configuration;
    
    $users = send_data($Configuration["NFS"]["Domain"], ["command" => "getexamstudents"]);
    return ($users);
}

