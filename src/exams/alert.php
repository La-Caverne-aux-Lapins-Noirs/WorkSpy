<?php

function exam_alert($local_users, Exam $exam)
{
    if ($exam != Exam::Soon)
	return ;
    foreach ($local_users as $lus)
    {
	if ($lus["mode"] != "x")
	    continue ;
	users_send_message(
	    ["username" => "technocore"], $lus,
	    "An exam will soon takes place in this room. Please save your work and leave."
	);
    }
}

