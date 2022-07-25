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

#
# New version: log as JSON; this file is picked up by Elastic Agent
#

import re
import certstream
import yaml
import json
from confusables import unconfuse
import os

certstream_url = 'wss://certstream.calidog.io'
basepath = os.path.dirname(os.path.realpath(__file__)) + '/'
log_suspicious = basepath + 'suspicious_domains.log'

# Main
def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        if message['data']['update_type'] == "PrecertLogEntry":
            return

        all_domains = message['data']['leaf_cert']['all_domains']

        force_break = False
        for domain in all_domains:

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
                    message["data"]["digital_footprint_match"] = alert
                    with open(log_suspicious, 'a') as f:
                        json.dump(message["data"], f)
                        f.write("\n")

if __name__ == '__main__':
    with open(basepath + 'keywords_alert.yaml', 'r') as f:
        y = yaml.safe_load(f)
        keywords_alert = y['keywords_alert']

    with open(basepath + 'keywords_ignore.yaml', 'r') as f:
        y = yaml.safe_load(f)
        keywords_ignore = y['keywords_ignore']

    # Start listening
    certstream.listen_for_events(callback, url=certstream_url)
