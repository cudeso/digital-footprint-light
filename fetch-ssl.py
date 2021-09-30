#!/usr/bin/env python
import certstream
import logging
import sys
from datetime import datetime
import time
import yaml
from confusables import unconfuse
import os
import json


certstream_url = 'wss://certstream.calidog.io/'
basepath = os.path.dirname(os.path.realpath(__file__)) + '/'
log_suspicious = basepath + 'suspicious_domains.log'
log_suspicious_json = basepath + 'suspicious_domains.json'

with open(basepath + 'keywords_alert.yaml', 'r') as f:
    y = yaml.safe_load(f)
    keywords_alert = y['keywords_alert']

with open(basepath + 'keywords_ignore.yaml', 'r') as f:
    y = yaml.safe_load(f)
    keywords_ignore = y['keywords_ignore']


def callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
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
                        now = time.strftime("%Y-%m-%d %H:%M:%S")
                        leaf_cert = message['data']['leaf_cert']
                        update_type = message['data']['update_type']
                        not_before = datetime.utcfromtimestamp(int(message['data']['leaf_cert']['not_after'])).strftime('%Y-%m-%d %H:%M:%S')
                        not_after = datetime.utcfromtimestamp(int(message['data']['leaf_cert']['not_after'])).strftime('%Y-%m-%d %H:%M:%S')
                        serial_number = message['data']['leaf_cert']['serial_number']
                        issuer = message['data']['leaf_cert']['subject']['aggregated']
                        fingerprint = message['data']['leaf_cert']['fingerprint']
                        ca = message['data']['leaf_cert']['issuer']['aggregated']

                        suspicious = {  "timestamp": now,
                                        "match": alert,
                                        "current_domain": current_domain,
                                        "issuer": issuer,
                                        "fingerprint": fingerprint,
                                        "update_type": update_type,
                                        "not_before": not_before,
                                        "not_after": not_after,
                                        "leaf_cert": leaf_cert }

                        with open(log_suspicious_json, 'a') as f_json:
                            json.dump(suspicious, f_json)
                            f_json.write("\n")
                        
                        with open(log_suspicious, 'a') as f_log_suspicious:
                            f_log_suspicious.write("{},{},{},{},{},{},{},{}\n".format(now,alert,current_domain,not_before,not_after,serial_number,fingerprint,ca))

        sys.stdout.flush()

if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(callback, url=certstream_url)
