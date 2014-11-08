# -- coding: utf-8 --

from scrapy.contrib.linkextractors import LinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from scrapy.selector import Selector
#from quickscan.items import injected_resp
#from quickscan.loginform import fill_login_form
from urlparse import urlparse, parse_qsl, urljoin

from scrapy.http.cookies import CookieJar
from cookielib import Cookie

from lxml.html import soupparser, fromstring
import lxml.etree
import lxml.html
import urllib
import re
import sys
import cgi
import requests
import string
import random

#from IPython import embed

class Quickscan(CrawlSpider):
    name = 'quickscan_spider'

    # If you're logging into a site with a logout link, you'll want to
    # uncomment the rule below and comment the shorter one right after to
    # prevent yourself from being logged out automatically
    rules = (Rule(LinkExtractor(), callback='parse_resp', follow=True), )

    def __init__(self, *args, **kwargs):
        """
        Handles args and logging in
        """
        super(Quickscan, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        hostname = urlparse(self.start_urls[0]).hostname
        # With subdomains
        self.allowed_domains = [hostname] # adding [] around the value seems to allow it to crawl subdomain of value
        self.delim = '9zqjx'

        # Login details
        self.login_user = kwargs.get('user')
        if self.login_user == 'None':
            self.login_user = None
        else:
            # Don't hit links with 'logout' in them since self.login_user exists
            self.rules = (Rule(LinkExtractor(deny=('logout')), callback='parse_resp', follow=True), )
        if kwargs.get('pw') == 'None' and self.login_user is not None:
            self.login_pass = raw_input("Please enter the password: ")
        else:
            self.login_pass = kwargs.get('pw')

        # HTTP Basic Auth
        self.basic_auth = kwargs.get('basic')
        if self.basic_auth == 'true':
            self.http_user = self.login_user
            self.http_pass = self.login_pass

    def parse_start_url(self, response):
        """
        Creates the test requests for the start URL as well as the request for robots.txt
        """
        u = urlparse(response.url)
        self.base_url = u.scheme+'://'+u.netloc
        robots_url = self.base_url+'/robots.txt'
        robot_req = [Request(robots_url, callback=self.robot_parser)]
        reqs = self.parse_resp(response)
        yield robot_req

    #### Handle logging in if username and password are given as arguments ####
    def start_requests(self):
        """
        If user and pw args are given, pass the first response to the login handler
        otherwise pass it to the normal callback function
        """
        if self.login_user and self.login_pass:
            if self.basic_auth == 'true':
                yield Request(url=self.start_urls[0]) # Take out the callback arg so crawler falls back to the rules' callback
            else:
                yield Request(url=self.start_urls[0], callback=self.login)
        else:
            yield Request(url=self.start_urls[0]) # Take out the callback arg so crawler falls back to the rules' callback

    def login(self, response):
        """
        Fill out the login form and return the request
        """
        self.log('Logging in...')
        try:
            args, url, method = fill_login_form(response.url, response.body, self.login_user, self.login_pass)
            return FormRequest(url,
                              method=method,
                              formdata=args,
                              callback=self.confirm_login,
                              dont_filter=True)

        except Exception:
            self.log('Login failed') # Make this more specific eventually
            return Request(url=self.start_urls[0], dont_filter=True) # Continue crawling

    def confirm_login(self, response):
        ''' Check that the username showed up in the response page '''
        if self.login_user.lower() in response.body.lower():
            self.log('Successfully logged in (or, at least, the username showed up in the response html)')
            return Request(url=self.start_urls[0], dont_filter=True)
        else:
            self.log('FAILED to log in! (or at least cannot find the username on the post-login page which may be OK)')
            return Request(url=self.start_urls[0], dont_filter=True)
    ###########################################################################

    def robot_parser(self, response):
        """
        Parse the robots.txt file and create Requests for the disallowed domains
        """
        disallowed_urls = set([])
        for line in response.body.splitlines():
            if 'disallow: ' in line.lower():
                try:
                    address = line.split()[1]
                except IndexError:
                    # In case Disallow: has no value after it
                    continue
                disallowed = self.base_url+address
                disallowed_urls.add(disallowed)
        reqs = [Request(u, callback=self.parse_resp) for u in disallowed_urls if u != self.base_url]
        for r in reqs:
            self.log('Added robots.txt disallowed URL to our queue: '+r.url)
        return reqs

    def parse_resp(self, response):
        """
        The main response parsing function, called on every response from a new URL
        Checks for XSS in headers and url
        """
        reqs = []
        orig_url = response.url
        body = response.body

        try:
            # soupparser will handle broken HTML better (like identical attributes) but god damn will you pay for it
            # in CPU cycles. Slows the script to a crawl and introduces more bugs.
            doc = lxml.html.fromstring(body, base_url=orig_url)
        except lxml.etree.ParserError:
            self.log('ParserError from lxml on %s' % orig_url)
            return # Might fuck up here
        except lxml.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % orig_url)
            return # Might fuck up here

        # Grab iframe source urls if they are part of the start_url page
        iframe_reqs = self.make_iframe_reqs(doc, orig_url)
        for req in iframe_reqs:
            yield req

        yield Response_analyzer(doc, body, orig_url)

    def make_iframe_reqs(self, doc, orig_url):
        """
        Grab the <iframe src=...> attribute and add those URLs to the
        queue should they be within the start_url domain
        """

        parsed_url = urlparse(orig_url)
        iframe_reqs = []
        iframes = doc.xpath('//iframe/@src')
        frames = doc.xpath('//frame/@src')

        all_frames = iframes + frames

        url = None
        for i in all_frames:
            if type(i) == unicode:
                i = str(i).strip()
            # Nonrelative path
            if '://' in i:
                # Skip iframes to outside sources
                try:
                    if self.base_url in i[:len(self.base_url)+1]:
                        url = i
                except IndexError:
                    continue
            # Relative path
            else:
                url = urljoin(orig_url, i)

            if url:
                iframe_reqs.append(Request(url))

        #if len(iframe_reqs) > 0:
        return iframe_reqs

class Response_analyzer():
    """
    Returns either None or a list of items
    """

    def __init__(self, doc, body, orig_url):
        print '       ' + orig_url

