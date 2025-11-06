<?php

// On ne peut pas effectuer une écriture de taille supérieure à 4k, donc
// on éclate tout. Le séparateur de commande devient tabulation verticale.
function hand_packet($data)
{
    $data = json_encode($data, JSON_UNESCAPED_UNICODE)."\v";
    $datatab = str_split($data, 2048);
    $datatab[] = "stop\v\n";
    $data = implode("\n", $datatab);
    $ship = "/tmp/.wsidle_msg".uniqid();
    file_put_contents($ship, "");
    system("chmod 600 $ship");
    file_put_contents($ship, $data);
    return ($ship);
}
