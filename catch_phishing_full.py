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
# - screenshot via Tor
# - notification of new potential phishing domains via Telegram bot

import re
import certstream
import entropy
import yaml

# @@ I'm using telepot to send Telegram notifications
import telepot
# @@

# @@
# @@ adding screenshot functionality via Tor <3
from tbselenium.utils import start_xvfb, stop_xvfb
from tbselenium.tbdriver import TorBrowserDriver
from os.path import join, dirname, realpath
# @@

# @@ I'm exposing a webserver to serve the blacklist to pi-hole
from http.server import BaseHTTPRequestHandler
import socketserver
import threading
# @@

# @@
# @@ I want to be able to produce RFC 5424 compliant messages
import logging
# @@


from Levenshtein import distance
from tld import get_tld
from confusables import unconfuse

# @@
# @@ convert localtime to UTC (good for logging)
import datetime
utc_datetime = datetime.datetime.utcnow()
# @@

# @@ Reading config file
with open("config_full.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
threshold = cfg['phishingcatcher_threshold']

# @@
# @@ Setting up the Telegram bot here (https://telepot.readthedocs.io/en/latest/#id5)
bot = telepot.Bot(cfg['phishingcatcher_bot_APIKEY'])
telegram_user = cfg['phishingcatcher_bot_user_id']
# @@

certstream_url = 'wss://certstream.calidog.io'

# @@ blacklist filename here
pihole_blacklist = cfg['phishingcatcher_blacklist_file']
# @@

# @@ logfile here and logger intialized
log_file = cfg['phishingcatcher_log_file']
log_file = cfg['phishingcatcher_log_file']

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s',
                    datefmt=utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    filename=log_file,
                    filemode='w')
# @@ defining logging areas
blacklisting = logging.getLogger('phishingcatcher.blacklisting')
evaluating = logging.getLogger('phishingcatcher.evaluating')
# @@

# @@ webserver configuration (remember to use PORT>1024, you don't want Python to run as root don't you?)
IP = cfg['phishingcatcher_blacklist_addr']
PORT = cfg['phishingcatcher_blacklist_port']
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
# @@ headers here
        self.send_response(200)
        self.send_header('Content-type', 'plain/text')
        self.end_headers()
        with open(pihole_blacklist, 'rb') as file:
            self.wfile.write(file.read())
httpd = socketserver.TCPServer((IP, PORT), Handler)
# @@

# @@
# @@ setting up screenshot web driver
DEFAULT_XVFB_WIN_W = cfg['phishingcatcher_screenshot_width']
DEFAULT_XVFB_WIN_H = cfg['phishingcatcher_screenshot_height']
Tor_Path = cfg['phishingcatcher_screenshot_tor_path']
xvfb_display = start_xvfb(win_width=DEFAULT_XVFB_WIN_W,win_height=DEFAULT_XVFB_WIN_H)
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
            evaluating.debug('%s suspicious_tld added score:%s', domain, score,)

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
    evaluating.debug('%s high_entropy added score:%s', domain, score,)

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]
        # ie. detect fake .com (ie. *.com-account-management.info)
        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10
            evaluating.debug('%s fake_tld added score:%s', domain, score,)

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]
            evaluating.debug('%s matching_keyword(%s) added score:%s', domain, word, score,)

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70
                evaluating.info('%s keyword_levenshtein(%s)(%s) added score:%s', domain, word, key, score,)

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3
        evaluating.debug('%s many_hypens added score:%s', domain, score,)

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3
        evaluating.debug('%s nested_subdomains added score:%s', domain, score,)

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" in message['data']['chain'][0]['subject']['aggregated']:
                score += 10
                evaluating.debug('%s letsencrypt_CA added score:%s', domain, score,)

# @@ Triggering the bot and the blacklist only when the score is "too damn high" 
            if score >= threshold :
                with open(pihole_blacklist, 'a') as f:
# @@ Excluding wildcard registrations here
                    if domain.startswith("*."):
                        blacklisting.info("\nWildcard found! I will not add: " + domain + " to the file " + pihole_blacklist)
                        blacklisting.info('%s skipped is_wildcard score:%s', domain, score,)
                    else:
                        # bot.sendMessage(telegram_user, domain + " added to the blacklist! Go to http://" + IP + ":" + str(PORT) + "/" + pihole_blacklist + " to see the results" )
                        blacklisting.info('%s blacklisted threshold(%d) score:%s', domain, threshold, score,)
                        f.write("{}\n".format(domain))
                        out_img = join(dirname(realpath(__file__)), domain + ".png")
                        with TorBrowserDriver(Tor_Path) as driver:
                            try: 
                                blacklisting.info("Taking screenshot of %s", domain)
                                driver.load_url('https://' + domain, wait_for_page_body=True)
                                driver.get_screenshot_as_file(out_img)
                                blacklisting.info("Screenshot is saved as %s" % out_img)
                                bot.sendPhoto(telegram_user, open(out_img, 'rb'), caption=domain + ' score=' + str(score) + ' threshold=' + str(threshold))
                            except:
                                blacklisting.info("Screenshot not saved")

# @@ defined a function to expose the webserver
def webserver():
    logging.info("webserver_started address:%s:%s", IP, str(PORT),)
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
    t = threading.Thread(target=webserver)
    t.start()
            
 # @@ thread is deprecated, using threading instead
 # @@ thread.start_new_thread(start_webserver, ())
 # @@

    certstream.listen_for_events(callback, url=certstream_url)
