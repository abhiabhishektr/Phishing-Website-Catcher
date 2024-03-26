import numpy as np
import regex as re
import requests
import dns.resolver
from ipaddress import ip_address
import whois
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup


def extract_features(url):
    # features extracted based on http://eprints.hud.ac.uk/id/eprint/24330/6/MohammadPhishing14July2015.pdf
    # total 9 features
    # 5 url Features
    # 	 - Url contains IP
    # 	 - Url length > 54
    # 	 - Occurance of // in Url after https:// initially
    # 	 - Occurance of @ or -
    # 	 - check if domain contains https
    #
    # 3 htmljs Features
    # 	 - Check number of redirects (Website Forwarding)
    # 	 - Check iframe
    # 	 - Check mouseover attribute
    #
    # 1 url Features
    #   - Check if domain Creation year is greater than 1 year
    #
    # 	X [Not taken ]Check if dns record exists
    #
    return url_features(url) + htmljs_features(url) + domain_features(url)


def url_features(url):
    # test positive for phishing url

    # test for ip address
    domain = urlparse(url).netloc
    try:
        url_ip = 1 if (ip_address(domain)) else 0
    except:
        url_ip = 0
    # Url Length
    url_len = 1 if (len(url) > 54) else 0

    # no of occurance of // > 1
    url_pos = 1 if (len(re.findall(r"\/\/", url)) > 1) else 0

    # @ or - in url
    url_at = 1 if ("@" in url or "-" in url) else 0

    # https  in url
    url_https = 1 if ("https" != url[:5]) else 0

    return [url_ip, url_len, url_pos, url_at, url_https]


def htmljs_features(url):
    try:
        # website redirect
        res = requests.get(url, timeout=0.80).text
        htf_redirect = 1 if (len(res.history) >= 3) else 0

        # popup Window requires selenium and slower to compute result

        # create BeautifulSoup instance
        soup = BeautifulSoup(res, "html.parser")

        # check if iframe exists
        htf_iframe = 1 if (soup.find_all("iframe")) else 0

        # check for onMouseOver
        htf_mouseover = 1 if (re.find_all(r"event.button ?== ?2", res)) else 0

        return [htf_redirect, htf_iframe, htf_mouseover]

    except Exception as err:
        # print(f"Error Sending request to url : {url}\n[Error]: {err}")
        return [0, 0, 0]


def domain_features(url):
    # parse domain
    domain = urlparse(url).netloc
    # get createtion date
    # dinfo = IPWhois(domain).lookup_rdap(depth=1)
    try:
        dinfo = whois.whois(domain)
        dom_date = 0
        if dinfo.creation_date:
            # get creation year
            # cr_yr = datetime.fromisoformat(dinfo.asn_date).year
            try:
                cr_yr = dinfo.creation_date.year
            except:
                cr_yr = dinfo.creation_date[0].year

            # check if creation date greater than 1 year
            if (datetime.now().year - cr_yr) < 1:
                dom_date = 1
            else:
                dom_date = 0
        else:
            # If not in whois , then phishing website
            dom_date = 1

        # Info not taken due to wait time for response
        #  dns Record
        # try:
        #     dom_dns = 1 if (not dns.resolver.resolve(domain)) else 0
        # except Exception as err:
        #     print(f"Error getting dns info : {err}")
        #     dom_dns = 1
    except Exception as err:
        # print("Error in whois : \n", err)
        dom_date = 1
    return [dom_date]
