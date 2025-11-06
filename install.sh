#!/bin/sh

systemctl daemon-reload
systemctl enable --now persoc.timer
systemctl list-timers persoc*
