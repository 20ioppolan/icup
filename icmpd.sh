#!/bin/bash

systemctl daemon-reload

systemctl enable icmpd.service

systemctl start icmpd.service