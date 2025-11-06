<?php

function send_data($packet)
{
    $packet["date"] = date("d/m/Y H:i:s", time());
    
}
