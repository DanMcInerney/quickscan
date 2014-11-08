# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
from scrapy.exceptions import DropItem
import HTMLParser
#from quickscan.items import vuln #, inj_resp
import re
import lxml.etree
import lxml.html
from lxml.html import fromstring
#from IPython import embed

class Resp_analyzer(object):
    def __init__(self):
        #self.url_param_vuln_items = []
        pass

    def process_item(self, item, spider):
        response = item['resp']
        meta = response.meta
        payload = meta['payload']
        #delim = meta['delim']
        resp_url = response.url
        body = response.body
        body = body.lower()
        doc = self.html_parser(body, resp_url)
        print resp_url, body[:20]
        print ''

    def html_parser(self, body, resp_url):
        try:
            # You must use lxml.html.soupparser or else candyass webdevs who use identical
            # multiple html attributes with injections in them don't get caught
            # That being said, soupparser is crazy slow and introduces a ton of
            # new bugs so that is not an option at this point in time
            doc = lxml.html.fromstring(body, base_url=resp_url)
        except lxml.etree.ParserError:
            self.log('ParserError from lxml on %s' % resp_url)
            return
        except lxml.etree.XMLSyntaxError:
            self.log('XMLSyntaxError from lxml on %s' % resp_url)
            return
        return doc
