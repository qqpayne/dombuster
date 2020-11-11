#!/usr/bin/env python3
import re
import json
import argparse
from scrapers import *
from pinger import *
from banner import print_banner

parser = argparse.ArgumentParser()
parser.add_argument('domain', type=str, help="Domain name to search for subdomains")
parser.add_argument('output', type=str, help="Name of output file")
parser.add_argument('-k', type=str, help="Path to JSON file with API keys. Currently only VirusTotal and SecurityTrail.")
parser.add_argument('-v', action="count", help="Verbosity (use twice if you want to see everything)")
parser.add_argument("-t", action='store_true', help="Use Google Certificate Transparency for additional SSL scraping (VERY SLOW, usually adds quite a few entries)")
parser.add_argument("--strict", action='store_true', help="Save only hosts that are online")
#parser.add_argument("-d", action='store_true', help="Use reverse DNS to find subdomains (slow)")
#parser.add_argument("-h", action='store_true', help="Use HTML parsing to find subdomains (VERY SLOW!)")

APISources = [VirusTotal, SecurityTrails]

def validate(domain):
	try:

		# all sources accept kaspersky.com, not https://kaspersky.com
		if args.domain.startswith("http"):
			domain = re.findall(r'[^/]*\.[a-zA-Z]{2,}$', args.domain)[0]
		else:
			domain = args.domain
		return domain
	
	except:
		print("Enter valid domain")
		exit(1)

def work(domain):
	sources = [child for child in Scraper.__subclasses__() if child not in APISources]
	if not args.t:
		sources.remove(GoogleTransparency)

	subdomains = [[] for i in range(len(sources))]
	threads = [sources[i](domain, subdomains[i], verbose) for i in range(len(sources))]
	if args.k:
		with open(args.k, "r") as f:
			keys = json.loads(f.read())

		for src in APISources:
			if str(src.__name__) in keys:
				if verbose > 0:
					print("[+] Found %s key" % src.__name__)
				subdomains.append([])
				threads.append(src(domain, subdomains[len(subdomains)-1], verbose, keys[src.__name__]))

	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()

	return subdomains

def merge(subdomains):
	overall = []
	for output in subdomains:
		overall += output
	return set(overall)

def beautify(output):
	to_delete = set()
	for entry in output:
		if entry.startswith(".") or entry.startswith("*"):
			to_delete.add(entry)
	output -= to_delete

	if args.strict:
		manager = PingManager(list(output), verbose)
		offlineHosts = manager.start()
		output -= offlineHosts


def main():
	print_banner()
	domain = validate(args.domain)
	subdomains = work(domain)
	overall = merge(subdomains)
	beautify(overall)

	with open(args.output, "w+") as f:
		for subdomain in overall:
			f.write("%s\n" % subdomain)

	if args.strict:
		print("\nFinished. There are %d online hosts on subdomains for %s" % (len(overall), domain))
	else:
		print("\nFinished. There are %d subdomains for %s" % (len(overall), domain))

if __name__ == "__main__":
	args = parser.parse_args()
	verbose = 0 if (args.v is None) else args.v
	main()




