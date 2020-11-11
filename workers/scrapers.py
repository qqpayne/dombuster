import re
import time
import random
from threading import Thread
import json
import requests
from workers.timer import format_seconds

class Scraper(Thread):

	def __init__(self, url, domain, subdomains, pages=False, verbosity=0, start_time=0):
		Thread.__init__(self)
		self.domain = domain
		self.subdomains = subdomains
		self.url = url
		self.verbosity = verbosity
		self.pages = pages
		self.ses = requests.Session()
		self.start_time = start_time

	def run(self):
		if self.verbosity > 0:
			print("%s Starting scraping subdomains on %s" % (format_seconds(time.time()-self.start_time), self.__class__.__name__))
		self.scrape()
		if self.verbosity > 0:
			print("%s Found %d entries on %s" % (format_seconds(time.time()-self.start_time), len(self.subdomains), self.__class__.__name__))
		
	def request(self, query, page):
		url = self.url.format(query=query, page=page)
		try:
			response = self.ses.get(url)
		except:
			return 0
		return response

	def extractURLs(self, response):
		response = response.text
		try:
			subdoms = re.findall(r'[\w\.]+\.%s' % self.domain, response)
		except:
			return 0

		return subdoms

	def wait(self):
		time.sleep(random.randint(1, 5))
		return

	def query(self):
		if self.pages:
			visited = []
			for item in self.subdomains:
				if item not in visited and len(visited) <= 10:
					visited.append(item)
			visited = ' -'.join(visited)
			query = "site:%s -www.%s %s" % (self.domain, self.domain, visited)
		else:
			query = "%s" % self.domain

		return query

	def paging(self, page):
		return page+10

	def scrape(self):
		page = 0
		retries = 0

		while True:
			query = self.query()
			try:
				response = self.request(query, page)
				newUrls = self.extractURLs(response)
			except:
				return

			if self.verbosity > 1:
				for i in range(len(newUrls)):
					print("%s %s, found on %s" % (format_seconds(time.time()-self.start_time), newUrls[i], self.__class__.__name__))

			if self.pages:
				# If our source have pages, then check if new querry gave us new urls
				# If it don't, we stop our search. Else - wait and proceed.

				if retries >= 5 or len(newUrls) == 0:
					self.subdomains += newUrls
					return

				unique = 0
				for newurl in newUrls:
					if newurl not in self.subdomains:
						unique += 1
				self.subdomains += newUrls

				if unique == 0:
					page = self.paging(page)
					retries += 1

				self.wait()
			else:
				self.subdomains += newUrls
				return

class Google(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "https://google.com/search?q={query}&start={page}"
		pages = True
		super().__init__(url, domain, subdomains, pages, verbosity, start_time)

class Yahoo(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://search.yahoo.com/search?p={query}&b={page}'
		pages = True
		super().__init__(url, domain, subdomains, pages, verbosity, start_time)

class Baidu(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://www.baidu.com/s?pn={page}&wd={query}&oq={query}'
		pages = True
		super().__init__(url, domain, subdomains, pages, verbosity, start_time)

class DuckDuckGo(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://duckduckgo.com/d.js?q={query}&p={page}'
		pages = True
		super().__init__(url, domain, subdomains, pages, verbosity, start_time)

class RapidDNS(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://rapiddns.io/subdomain/{query}?full=1'
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

class crtDOTsh(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "https://crt.sh/?q={query}"
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

class GoogleTransparency(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch{query}{page}"
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def query(self):
		query = "?include_subdomains=true&domain=%s" % self.domain
		return query

	def paging(self, response):
		paging = "/page?p=%s" % response[3][1]
		return paging

	def extractURLs(self, response):
		subdoms = [response[1][i][1] for i in range(len(response[1]))]
		return subdoms

	def scrape(self):
		query = self.query()
		response = self.request(query, '')
		lastPage = json.loads(response.text[7:-2])[3][4]
		cooldown = time.time()

		while True:
			try:
				response = json.loads(response.text[7:-2])	
				newUrls = self.extractURLs(response)
			except:
				return

			if self.verbosity > 1:
				for i in range(len(newUrls)):
					print("%s %s, found on %s" % (time.time() - self.start_time, newUrls[i], self.__class__.__name__))

			if self.verbosity > 0:
				completion = 100 * response[3][3] // lastPage
				if (((time.time() - self.start_time) % 40) < 5) and (time.time() - cooldown) > 0:
					print("%s Google Certificate Transparency search %d%% completed" % (format_seconds(time.time()-self.start_time), completion))
					cooldown = time.time()+5 

			self.subdomains += newUrls
			page = self.paging(response)
			# page num equals last page num
			if (page is None) or (response[3][3] == lastPage):
				return
			response = self.request('', page)


class CertSpotter(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "https://api.certspotter.com/v1/issuances?domain={query}&include_subdomains=true&expand=dns_names"
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def extractURLs(self, response):
		subdoms = []
		json = response.json()
		for entry in json:
			subdoms += entry["dns_names"]
		return subdoms

class SiteDossier(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "http://www.sitedossier.com/parentdomain/{query}"
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

class ThreatMiner(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://www.threatminer.org/getData.php?e=subdomains_container&q={query}&t=0&rt=10&p=1'
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)


class AlienVault(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://otx.alienvault.com/otxapi/indicator/domain/passive_dns/{query}'
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def extractURLs(self, response):
		subdoms = []
		json = response.json()['passive_dns']
		return [json[i]['hostname'] for i in range(len(json))]

class ThreatCrowd(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={query}"
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def extractURLs(self, response):
		return response.json()['subdomains']

class HackerTarget(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://hackertarget.com/find-dns-host-records/'
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def request(self, query, page):
		cookie = self.validateCookie()
		data = {'theinput':self.domain, 'thetest':"hostsearch", "name_of_nonce_field":cookie, "_wp_http_referer":"/find-dns-host-records/"}
		headers = {'Referer':self.url}
		try:
			response = self.ses.post(self.url, data=data, headers=headers)
		except:
			return 0
		return response

	def validateCookie(self):
		req = self.ses.get(self.url)
		return re.findall(r'name_of_nonce_field" value="(\w+)"', req.text)[0]

class DNSDumpster(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time):
		url = 'https://dnsdumpster.com/'
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def request(self, query, page):
		cookie = self.validateCookie()
		cookies = {'csrftoken':cookie}
		data = {'csrfmiddlewaretoken':cookie, 'targetip':self.domain}
		headers = {'Referer':self.url}
		try:
			response = self.ses.post(self.url, cookies=cookies, data=data, headers=headers)
		except:
			return 0
		return response

	def validateCookie(self):
		req = self.ses.get(self.url)
		return re.findall(r'csrfmiddlewaretoken" value="(\w+)"', req.text)[0]

class SecurityTrails(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time, apikey):
		url = 'https://api.securitytrails.com/v1/domain/{query}/subdomains'
		self.apikey=apikey
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def request(self, query, page):
		headers = {'apikey':self.apikey}
		url = self.url.format(query=query, page=page)
		try:
			response = self.ses.get(url, headers=headers)
		except:
			return 0
		return response

	def extractURLs(self, response):
		response = response.json()
		return [response['subdomains'][i]+"."+self.domain for i in range(len(response['subdomains']))]

class VirusTotal(Scraper):

	def __init__(self, domain, subdomains, verbosity, start_time, apikey):
		url = 'https://www.virustotal.com/api/v3/domains/{query}/subdomains'
		self.apikey=apikey
		super().__init__(url, domain, subdomains, verbosity=verbosity, start_time=start_time)

	def request(self, query, page):
		headers = {'x-apikey':self.apikey}
		url = self.url.format(query=query, page=page)
		try:
			response = self.ses.get(url, headers=headers)
		except:
			return 0
		return response

	def extractURLs(self, response):
		response = response.json()
		return [response['data'][i]['id'] for i in range(len(response['data']))]
