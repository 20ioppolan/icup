#!/bin/bash

cp icmpd.py /etc/icmpd

cp icmpd.service /etc/systemd/system/

systemctl daemon-reload

systemctl enable icmpd.service

systemctl start icmpd.service