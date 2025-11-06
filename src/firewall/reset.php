<?php

function firewall_reset()
{
    system("nft flush ruleset; nft add table inet filter");
}

