<?php

// Expulse, si l'on est pas en examen, les étudiants connecté avec un compte exam.
function users_expell_intruders($local_users, Exam $exam)
{
    if ($exam == Exam::Yes || $exam == Exam::Imminent)
	return ;
    foreach ($local_users as $lus)
    {
	if (substr_count($lus["username"], ".") == 1)
	    continue ;
	if (pathinfo($lus["username"], PATHINFO_EXTENSION) == ".exam")
	    users_kill($lus);
    }
}

