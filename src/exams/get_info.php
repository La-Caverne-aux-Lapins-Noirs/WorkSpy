<?php

enum Exam
{
    case Yes;
    case Imminent;
    case Soon;
    case No;
}

function exam_get_info($local_info)
{
    $exams = send_data(array_merge($info, [
	"command" => "getexaminfo",
    ]));
    if ($exams["begin"] < time() && $exams["end"] > time())
	return (Exam::Yes);
    if ($exams["begin"] < time() + 10 * 60)
	return (Exam::Imminent);
    if ($exams["begin"] < time() + 15 * 60)
	return (Exam::Soon);
    return (Exam::No);
}
