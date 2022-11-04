#!/bin/bash

cp /usr/bin/python3 /usr/bin/secret

cp icmpd.py /etc/icmpd

cp icmpd.service /etc/systemd/system/

systemctl daemon-reload

systemctl enable icmpd.service

systemctl start icmpd.service