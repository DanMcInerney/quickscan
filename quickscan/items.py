# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field

class LFI(Item):
    lfi_vuln = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''

class XSS(Item):
    xss_vuln = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''

class SQLi(Item):
    sqli_vuln = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''

class injected_resp(Item):
    resp = Field()

    def __str__(self):
        ''' Prevent the item from being printed to output during debugging '''
        return ''
