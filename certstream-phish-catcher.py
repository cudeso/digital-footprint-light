#!/usr/bin/env python
#
# Based on catch_phishing by @x0rz
# https://github.com/x0rz/phishing_catcher
#
# Known error: "UnicodeError: ('IDNA does not round-trip', b'xn--einla-pqa', b'einlass')"
#   Caused by domains with 'german beta' ; idna 2008 fixes this ; doesn't prevent the script from continuing
#
# Best run from screen
#   /usr/bin/screen -dmS catcher <me>.py
# To rotate logs, restart it regularly
#   /usr/bin/screen -S catcher -p 0 -X quit
# Or run from the monitoring script (for e-mail alerts)
#
# keywords_alert.yaml : keywords to trigger on
#     but ignore the alert if the domain contains something from keywords_ignore.yaml
#

import re
import certstream
import entropy
import tqdm
import yaml
from datetime import datetime
import time
from termcolor import colored, cprint
import smtplib
from email.mime.text import MIMEText
from confusables import unconfuse
import os

certstream_url = 'wss://certstream.calidog.io'
basepath = os.path.dirname(os.path.realpath(__file__)) + '/'
log_suspicious = basepath + 'suspicious_domains.log'
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

# Main
def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        force_break = False
        for domain in all_domains:
            pbar.update(1)

            current_domain = domain.lower()
            uc_current_domain = unconfuse(current_domain)

            for ignore in keywords_ignore:
                if ignore in current_domain or ignore in uc_current_domain:
                    force_break = True
                    break
            if force_break:
                break

            for alert in keywords_alert:
                if alert in current_domain or alert in uc_current_domain:

                    not_before = datetime.utcfromtimestamp(int(message['data']['leaf_cert']['not_after'])).strftime('%Y-%m-%d %H:%M:%S')
                    not_after = datetime.utcfromtimestamp(int(message['data']['leaf_cert']['not_after'])).strftime('%Y-%m-%d %H:%M:%S')
                    serial_number = message['data']['leaf_cert']['serial_number']
                    fingerprint = message['data']['leaf_cert']['fingerprint']
                    ca = message['data']['chain'][0]['subject']['aggregated']

                    tqdm.tqdm.write("[+] Match found {}".format(colored(current_domain, 'red', attrs=['underline', 'bold'])))
                    tqdm.tqdm.write("      Matched on {}".format(alert))
                    tqdm.tqdm.write("      [Details] Not before {}, Not after {}, Serial {}".format(not_before,not_after,serial_number))
                    tqdm.tqdm.write("      [Details] Fingerprint {}, CA {}".format(fingerprint,ca))

                    with open(log_suspicious, 'a') as f:
                        now = time.strftime("%Y-%m-%d %H:%M:%S")
                        f.write("{},{},{},{},{},{},{},{}\n".format(now,alert,current_domain,not_before,not_after,serial_number,fingerprint,ca))
if __name__ == '__main__':
    with open(basepath + 'keywords_alert.yaml', 'r') as f:
        y = yaml.safe_load(f)
        keywords_alert = y['keywords_alert']

    with open(basepath + 'keywords_ignore.yaml', 'r') as f:
        y = yaml.safe_load(f)
        keywords_ignore = y['keywords_ignore']

    # Start listening
    certstream.listen_for_events(callback, url=certstream_url)
