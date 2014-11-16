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

        # Determine whether we payload all inputs in 1 request or multi
        # By default (without --fast arg), payload inputs 1 per req
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
        parsed_url = urlparse(orig_url)
        reqs = []

        url_params = self.get_url_params(parsed_url)
        # If no params, then we can test the end of the URL
        # WORK: just add a %s on to end_of_url and it's ready to be payloaded
        if url_params is not None:
            if orig_url.endswith('/'):
                end_of_url = orig_url
            else:
                end_of_url = orig_url + '/'
            # If there are params and we still want to test end of URL minus the params
            #            scheme                  netloc          path
            #end_of_url = parsed_url[0] + '://' + parsed_url[1] + parsed_url[2]

        form_data = self.get_form_params(orig_url, parsed_url, doc)
        if form_data is not None:
            for form in form_data:
                print 'FORM:', form

        #headers = ... user-agent, referer, shellshock, cookies

#        if fast not None:
#            # put all the inputs into one request
#            pass
#        else:
#            # make one request per input
#            pass
        #{'urls':[urls], 'headers':
        print 'URL PARAMS:', url_params
        print ''
        if len(reqs) > 0:
            return reqs

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

    def get_url_params(self, parsed_url):
        """
        Get the URL parameters
        """
        full_params = parsed_url.query
        params = parse_qsl(full_params) #parse_qsl rather than parse_ps in order to preserve order
        if len(params) > 0:
            return params

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


