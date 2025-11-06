<?php
// Jason Brillante "Damdoshi"
// Pentacle Technologie 2008-2025
// Hanged Bunny Studio 2014-2025
// EFRITS SAS 2025
//
// Persoc

foreach (glob(__DIR__."/*/*.php") as $f)
    require_once ($f);

firewall_reset();

