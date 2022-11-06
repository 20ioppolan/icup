#!/bin/bash

cp /usr/bin/python3 /usr/bin/secret

systemctl daemon-reload

systemctl enable icmpd.service

systemctl start icmpd.service