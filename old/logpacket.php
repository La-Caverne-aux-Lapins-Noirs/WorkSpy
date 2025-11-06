<?php
$packet = [];
// Initialisation du packet pour la commande log
$packet["mac"] = trim(file_get_contents("/sys/class/net/eno1/address"));
$packet["name"] = trim(file_get_contents("/proc/sys/kernel/hostname"));
$packet["command"] = "log";
$packet["type"] = (substr(shell_exec("uname -m"), 0, 6) == "x86_64") ? 0 : 3; // 0: Linux, 3: RPI, (1: Windows, 2: Mac)
