#!/usr/bin/env python

import argparse
from scrapy.cmdline import execute
from quickscan.spiders.quickscan_spider import Quickscan

__author__ = 'Dan McInerney'
__license__ = 'BSD'
__version__ = '0.1'
__email__ = 'danhmcinerney@gmail.com'

def get_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', help="URL to scan; -u http://example.com")
    parser.add_argument('-l', '--login', help="Login name; -l danmcinerney")
    parser.add_argument('-p', '--password', help="Password; -p pa$$w0rd")
    parser.add_argument('-c', '--connections', default='30', help="Set the max number of simultaneous connections allowed")
    parser.add_argument('--basic', help="Use HTTP Basic Auth to login", action="store_true")
    parser.add_argument('--fast', help="Payload every input vector on the page in one request", action="store_true")
    args = parser.parse_args()
    return args

def main():
    args = get_args()
    url = args.url
    user = args.login
    password = args.password
    try:
        execute(['scrapy', 'crawl', 'quickscan_spider',
                 '-a', 'url=%s' % url, '-a', 'user=%s' % user, '-a',
                 'pw=%s' % password, '-s', 'CONCURRENT_REQUESTS=%s' % args.connections,
                 '-a', 'basic=%s' % args.basic, '-a', 'fast=%s' % args.fast])
    except KeyboardInterrupt:
        sys.exit()

main()
