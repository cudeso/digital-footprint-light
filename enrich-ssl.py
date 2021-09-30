import os
import json
import random
import requests
import socket
import warnings
from ipwhois import IPWhois
from datetime import datetime
import time
from time import sleep


basepath = os.path.dirname(os.path.realpath(__file__)) + '/'
log_suspicious = basepath + 'suspicious_domains.log'
log_suspicious_json = basepath + 'suspicious_domains.json'


def get_webpage_title(request):
    try:
        page = request.text.strip()
        tit = re.search('<title>(.*?)</title>', page, re.IGNORECASE)
        if tit is not None:
            title = tit.group(1)
        else:
            title = ""
        return title
    except Exception as e:        
        return ""


def get_ASN_Infos(ipaddr):
    """
    Get Autonomous System Number informations linked to an ip address
    :param ipaddr: ip address of the website linked to the certificate common name
    :return: list of ASN infos: asn, asn_cidr, asn_country_code, asn_description, asn_abuse_email or the same with empty values
    """
    try:
        warnings.filterwarnings("ignore")
        obj = IPWhois(ipaddr)
        results = obj.lookup_rdap(depth=1)
        asn = results['asn']
        asn_cidr = results['asn_cidr']
        asn_country_code = results['asn_country_code']
        asn_description = results['asn_description']

        try:
            for entity in results['objects'].values():
                if 'abuse' in entity['roles']:
                    asn_abuse_email = entity['contact']['email'][0]['value']
                    break
        except Exception as e:
            asn_abuse_email = ""

        return asn, asn_cidr, asn_country_code, asn_description, asn_abuse_email

    except Exception as e:
        asn, asn_cidr, asn_country_code, asn_description, asn_abuse_email = "", "", "", "", ""
        return asn, asn_cidr, asn_country_code, asn_description, asn_abuse_email


def enrich(domain, useragent):
    headers = {'user-agent': useragent}
    proxy = {}
    url = "https://{}".format(domain)

    try:
        req = requests.get(url, headers=headers, proxies=proxy, timeout=5)

        status_code = req.status_code
        response_text = req.text
        response_headers = req.headers
        try:
            response_server = response_headers["Server"]
        except Exception as e:
            response_server = ""
        try:
            response_last_modified = response_headers["Last-Modified"]
        except Exception as e:
            response_last_modified = ""
        
        page_title = get_webpage_title(req)
        ipaddr = socket.gethostbyname(domain)
        asn, asn_cidr, asn_country_code, asn_description, asn_abuse_email = get_ASN_Infos(ipaddr)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        
        result = {  "enriched_status": "ok",
                    "enriched_timestamp": now,
                    "enriched_domain": domain,
                    "status_code": status_code, 
                    "response_server": response_server, 
                    "response_last_modified": response_last_modified,
                    "page_title": page_title,
                    "ipaddr": ipaddr,
                    "asn": asn,
                    "asn_cidr": asn_cidr,
                    "asn_country_code": asn_country_code,
                    "asn_description": asn_description,
                    "asn_abuse_email": asn_abuse_email                    
                    }
        return result

    except Exception as ex:
        return { "enriched_status": "Unable to contact site" }


def main(ua):
    tested_domains = {}

    with open(log_suspicious_json, 'r') as reader:
        data = True
        while data:
            data = reader.readline()
            useragent = random.choice(ua)
            if data:
                data_json = json.loads(data)

                if data_json["update_type"] == "X509LogEntry":
                    all_domains = data_json["leaf_cert"]["all_domains"]

                    if len(all_domains) > 0:
                        for domain in all_domains:
                            test_domain = domain
                            if "*." in domain:
                                test_domain = domain.replace("*.","www.")

                            do_enrichment = True
                            for el in tested_domains:
                                if el == test_domain:
                                    do_enrichment = False
                                    break

                            if do_enrichment:
                                update_json = { "timestamp": data_json["timestamp"],
                                                "match": data_json["match"],
                                                "current_domain": data_json["current_domain"],
                                                "update_type": data_json["update_type"],
                                                "not_before": data_json["not_before"],
                                                "not_after": data_json["not_after"],
                                                "leaf_cert": data_json["leaf_cert"],
                                                "enriched": enrich(test_domain, useragent)
                                                 }

                                tested_domains[test_domain] = update_json

    reader.close()

    with open("certificate_stream_for_elk.json", "w") as writer:
        for el in tested_domains:
            json.dump(tested_domains[el], writer)
            writer.write("\n")


if __name__ == '__main__':

    try:
        ua = open('useragent_list.txt').read().splitlines()
    except:
        ua = ['Mozilla/5.0 (Windows NT 6.2; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0']
    main(ua)
