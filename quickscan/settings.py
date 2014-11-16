#
#     http://doc.scrapy.org/en/latest/topics/settings.html
#

# Uncomment below in order to disallow redirects
#REDIRECT_ENABLED = False

# Uncomment this to lessen the spider's output
#LOG_LEVEL = 'INFO'

BOT_NAME = 'quickscan_spider'

SPIDER_MODULES = ['quickscan.spiders']
NEWSPIDER_MODULE = 'quickscan.spiders'

# For adding javascript rendering
#DOWNLOAD_HANDLERS = {'http':'quickscan.scrapyjs.dhandler.WebkitDownloadHandler',
#                     'https': 'quickscan.scrapyjs.dhandler.WebkitDownloadHandler'}

# 100 (first): Make sure there's no duplicate requests that have some value changed
# 200 (second): Make sure there's a random working User-Agent header set if that value's not injected with the test string
DOWNLOADER_MIDDLEWARES = {'quickscan.middlewares.RandomUserAgentMiddleware': 100,
                          'scrapy.contrib.downloadermiddleware.httpauth.HttpAuthMiddleware': 200}

COOKIES_ENABLED = True
#COOKIES_DEBUG = True

# Prevent duplicate link crawling
# Bloom filters are way more memory efficient than just a hash lookup
DUPEFILTER_CLASS = 'quickscan.bloomfilters.BloomURLDupeFilter'
#DUPEFILTER_CLASS = 'scrapy.dupefilter.RFPDupeFilter'

ITEM_PIPELINES = {'quickscan.pipelines.Resp_analyzer':100}

#FEED_FORMAT = 'csv'
#FEED_URI = 'example.txt'

CONCURRENT_REQUESTS = 30
DOWNLOAD_DELAY = 0

