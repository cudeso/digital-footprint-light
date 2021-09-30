#!/bin/sh

NOW=`/bin/date '+%Y-%m-%d'`
CERTSTREAM_LOG="suspicious_domains.log"
CERTSTREAM_LOG_JSON="suspicious_domains.json"
CERTSTREAM_PY="fetch-ssl.py"
OUTPUT_PATH=/home/user/digital-footprint-light/
MAIL_FROM="user@localhost"
RCPT_TO="user@localhost"

# From get_phishtank script
REPORTED_PHISH="reported_phish.out"

# First we mail the log results
if [ `cat $OUTPUT_PATH/$CERTSTREAM_LOG | wc -l ` -gt 1 ]
then
        (
         echo "From: Domain monitor <$MAIL_FROM>"
         echo "To: Domain monitor <$RCPT_TO>"
         echo "Subject: Domain monitor - $NOW"
         echo "MIME-Version: 1.0"
         echo "Content-Type: text/plain"
         echo "Content-Disposition: inline"
         echo
	 echo "Phishtank / Openphish matches"
	 echo "-----------------------------"
	 echo
	 /bin/cat $OUTPUT_PATH/$REPORTED_PHISH
	 echo
         echo "Certstream matches"
         echo "-------------------"
         echo
         /bin/cat $OUTPUT_PATH/$CERTSTREAM_LOG | tail -n +2 | cut -d , -f 3 | sort | uniq -c | sort -nr
         echo
	 echo
	 echo "Full log"
	 echo "-----------"
	 echo 
	 /bin/cat $OUTPUT_PATH/$CERTSTREAM_LOG
	 echo
         echo
        ) | /usr/sbin/sendmail -r $MAIL_FROM $RCPT_TO 
fi

# Stop catcher
/usr/bin/screen -S catcher -p 0 -X quit

# Copy and archive logs
/bin/cp $OUTPUT_PATH/$CERTSTREAM_LOG $OUTPUT_PATH/$CERTSTREAM_LOG-$NOW
/bin/cp $OUTPUT_PATH/$CERTSTREAM_LOG $OUTPUT_PATH/$CERTSTREAM_LOG-forelk
/bin/cp $OUTPUT_PATH/$CERTSTREAM_LOG_JSON $OUTPUT_PATH/$CERTSTREAM_LOG_JSON-$NOW
/bin/gzip --force $OUTPUT_PATH/$CERTSTREAM_LOG-$NOW
/bin/gzip --force $OUTPUT_PATH/$CERTSTREAM_LOG_JSON-$NOW
/bin/rm $OUTPUT_PATH/$CERTSTREAM_LOG
/bin/rm $OUTPUT_PATH/$CERTSTREAM_LOG_JSON

# Start catcher
/usr/bin/screen -dmS catcher $OUTPUT_PATH/$CERTSTREAM_PY
