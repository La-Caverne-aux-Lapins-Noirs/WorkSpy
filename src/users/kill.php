<?php

function users_kill($local_user)
{
    `pkill -u $local_user["username"]`;
    `sleep 1`;
    `pkill -u -9 $local_user["username"]`;
    persoc_log("killing {$local_user["username"]}");
}

