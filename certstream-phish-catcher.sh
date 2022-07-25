#!/bin/sh

CERTSTREAM_LOG="suspicious_domains.log"
CERTSTREAM_PY="certstream-phish-catcher.py"
OUTPUT_PATH=/home/koenv/digital-footprint-light/

# Stop catcher
/usr/bin/screen -S catcher -p 0 -X quit

rm $OUTPUT_PATH/$CERTSTREAM_LOG

# Start catcher (cleans logs)
/usr/bin/screen -dmS catcher $OUTPUT_PATH/$CERTSTREAM_PY
