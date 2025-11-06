<?php

// Expulse, si l'on est en examen, les étudiants n'étant pas en examen.
function exam_expell_intruders($local_users, Exam $exam)
{
    if ($exam == Exam::Soon || $exam == Exam::No)
	return ;
    $users = exam_get_users();
    foreach ($local_users as $lus)
    {
	if ($lus["mode"] != "x")
	    continue ;
	$fnd = false;
	foreach ($users as $xus)
	{
	    if ($xus["username"] != $lus["username"])
		continue ;
	    $fnd = true;
	    break ;
	}
	if ($fnd == false)
	    users_kill($lus);
    }
}
