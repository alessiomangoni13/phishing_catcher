#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ...
# Slightly modified to be able do the following:
# - exclude wildcards in domains
# - create a blacklist file and expose it via http server (to feed a Pihole)
# - notification of new potential phishing domains via Telegram bot

import re

import certstream
import entropy
import tqdm
import yaml

# @@ I'm using telepot to send Telegram notifications
import telepot
# @@

# @@ I'm exposing a webserver to serve the blacklist to pi-hole
import ipaddress
import SimpleHTTPServer
import SocketServer
import thread
# @@

from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld

from confusables import unconfuse

# @@ Reading config file
with open("config.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

# @@
# @@ Setting up the Telegram bot here (https://telepot.readthedocs.io/en/latest/#id5)
bot = telepot.Bot(cfg['phishingcatcher_bot_APIKEY'])
telegram_user = cfg['phishingcatcher_bot_user_id']
# @@

certstream_url = 'wss://certstream.calidog.io'

# @@ blacklist filename here
pihole_blacklist = cfg['phishingcatcher_blacklist_file']
# @@

log_suspicious = cfg['phishingcatcher_log_file']

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

# @@ webserver configuration (remember to use PORT>1024, you don't want Python to run as root don't you?)
IP = cfg['phishingcatcher_blacklist_addr']
PORT = cfg['phishingcatcher_blacklist_port']
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer((IP, PORT), Handler)
# @@

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy.shannon_entropy(domain)*50))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]
        # ie. detect fake .com (ie. *.com-account-management.info)
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                score += 10
# @@
# Don't need to print all this stuff
            '''if score >= 100:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
            elif score >= 90:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 65:
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))'''

# @@ Triggering the bot and the blacklist only when the score is "too damn high" 
            if score >= cfg['phishingcatcher_threshold']:
                with open(pihole_blacklist, 'a') as f:
# @@ Excluding wildcard registrations here
                    if domain.startswith("*."):
                        print("\nWildcard found! I will not add: " + domain + "to the file " + pihole_blacklist)
                        bot.sendMessage(telegram_user, domain + " added to the blacklist! Go to http://" + IP + ":" + str(PORT) + "/" + pihole_blacklist + " to see the results" )
                    else:
                        f.write("{}\n".format(domain))

# @@ defined a function to expose the webserver
def start_server():
    print "\nblacklist served at: http://" + IP + ":" + str(PORT) + "/" + pihole_blacklist
    httpd.serve_forever()
# @@


if __name__ == '__main__':
    with open('suspicious.yaml', 'r') as f:
        suspicious = yaml.safe_load(f)

    with open('external.yaml', 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])
            
 # @@ creating a new thread for the webserver           
    thread.start_new_thread(start_server, ())
 # @@

    certstream.listen_for_events(callback, url=certstream_url)
