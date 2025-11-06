<?php
$conf = [];
if (file_exists("/etc/persoc/persoc.dab"))
    $conf = json_decode(shell_exec("mergeconf -i /etc/perso/persoc.dab -of .json"), true);
else if (file_exists("/etc/wsidle/wsidle.dab"))
    $conf = json_decode(shell_exec("mergeconf -i /etc/wsidle/wsidle.dab -of .json"), true);
else
{
    $conf["NFS"]["Domain"] = "nfs.efrits.fr";
    $conf["NFS"]["IP"] = "192.168.200.1";
    $conf["LDAP"] = "192.168.200.1";
    $conf["CUSTOM"] = "192.168.200.1";
}

$nfs_server = $conf["NFS"]["Domain"]
$ip_nfs = $conf["NFS"]["IP"];
$ldap_server = $conf["LDAP"];
$net_server = $conf["CUSTOM"];
