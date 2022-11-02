#!/bin/bash

cp icmpd.py /etc/icmpd

systemctl daemon-reload

systemctl enable icmpd.service

systemctl start icmpd.service