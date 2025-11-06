<?php
// Un clef SSH doit déjà avoir été échangé.
function send_data($url, $data)
{
    $ship = hand_packet($data);
    $cmd = "cat $ship | ssh -o 'StrictHostKeyChecking no' infosphere_hand@$url -i /root/.ssh/ihk -p 4422 -tt infosphere_hand  2> /dev/null ; rm -f $ship";
    $ret = shell_exec($cmd);
    $ret = explode("\n", $ret);
    return (json_decode(end($ret), true));
}
