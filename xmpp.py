"""
Module to detect SSL Tampering of XMPP Servers
"""

import logging
from dns.resolver import query
from subprocess import check_output
from util import exiturl
from os import devnull

log = logging.getLogger(__name__)
FNULL = open(devnull, 'w')

destinations = None
root_domains = [
    "swissjabber.ch", "jabber.ru"
]  # These are the domains of the xmpp services we're checking
# Excluded jabber.org 'cos openssl was having trouble with ipv6
domains = {}  # This will be populated with the actual XMPP domains + sigs


def setup():
    for domain in root_domains:
        srv_record = query("_xmpp-client._tcp.%s" % domain, "SRV")[0]
        server_domain = srv_record.to_text().split(' ')[-1].rstrip()[:-1]
        sig = get_ssl_signature(server_domain, 5222)
        if sig != 0:
            domains[server_domain] = sig
            log.info("Got SSL signature of: %s" % domain)
        else:
            log.critical("Error getting SSL cert for %s" % domain)
    log.info("Signatures Retrieved")


def get_ssl_signature(host, port):
    command = ['openssl', 's_client', '-connect', '%s:%d' % (host, port),
               '-starttls', 'xmpp']
    openssl_output = check_output(command, stdin=FNULL, stderr=FNULL)
    openssl_output = openssl_output.decode("utf-8")
    # Openssl puts a lot of stuff in stderr for some reason
    if "BEGIN CERTIFICATE" in openssl_output:
        signature = openssl_output.split('BEGIN CERTIFICATE-----\n')[1]
        signature = signature.split('\n-----END CERTIFICATE')[0]
        return signature
    else:
        return 0


def checker(exit_desc, domain, expected_sig):
    exit = exiturl(exit_desc.fingerprint)
    tor_sig = get_ssl_signature(domain, 5222)
    if tor_sig != expected_sig:
        log.critical("ExitNode %s returned different SSL cert: %s" %
                     (exit, tor_sig))

def my_callback(output, exit_desc,proc_kill):
    #log.info(output)
    exit = exiturl(exit_desc.fingerprint)
    if "BEGIN CERTIFICATE" in output:
        signature = output.split('BEGIN CERTIFICATE-----\n')[1]
        signature = signature.split('\n-----END CERTIFICATE')[0]
        valid = False
        for domain in domains.iterkeys():
            if domains[domain]==signature:
                valid = True
        if not valid:
            log.critical("%s providing invalid signature: %s" % (exit,output))
    return True

def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    #log.info(run_cmd_over_tor.execute(['curl','-s','https://wtfismyip.com/'],output_callback=bam_callback))
    for domain in domains.iterkeys():
        #run_python_over_tor(checker, exit_desc, domain, domains[domain])
        run_cmd_over_tor.execute(['openssl', 's_client', '-connect', '%s:%d' % (domain, 5222),'-starttls', 'xmpp'],exit_desc,output_callback=my_callback)
        #openssl s_client -connect proxy.jabber.ru:5222 -starttls xmpp
