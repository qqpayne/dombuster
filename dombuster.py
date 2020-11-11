#!/usr/bin/env python3
import re
import json
import argparse
from workers.scrapers import *
from workers.resolver import *
from workers.pinger import *
from workers.whois import *
from banner import print_banner

parser = argparse.ArgumentParser()
parser.add_argument('domain', type=str, help="Domain name to search for subdomains")
parser.add_argument('output', type=str, help="Name of output file")
parser.add_argument('-k', type=str, help="Path to JSON file with API keys. Currently only VirusTotal and SecurityTrail.")
parser.add_argument('-v', action="count", help="Verbosity (use twice if you want to see everything)")
parser.add_argument("-t", action='store_true', help="Use Google Certificate Transparency for additional SSL scraping (VERY SLOW, usually adds quite a few entries)")
parser.add_argument("--strict", action='store_true', help="Save only hosts that are online")
parser.add_argument("--ip", action='store_true', help="Save IP address of subdomain")
parser.add_argument("--org", action='store_true', help="Save OrgName and NetRange from reverse whois lookup on subdomain")
parser.add_argument("--csv", action='store_true', help="Output in CSV (default: plaintext)")
#parser.add_argument("-d", action='store_true', help="Use reverse DNS to find subdomains (slow)")
#parser.add_argument("-h", action='store_true', help="Use HTML parsing to find subdomains (slow and useless)")

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
		offlineHosts = PingManager(list(output), verbose).start()
		output -= offlineHosts

	return output

def additionals(output):
	if args.ip:
		ips = ResolveManager(list(output), verbose).start()
		output = [(a,b) for a, b in zip(output, ips)]

	if args.org:
		if not args.ip:
			ips = ResolveManager(list(output), verbose).start()
			tuples = [(a,b) for a, b in zip(output, ips)]
			orgs = WhoisManager(tuples, verbose).start()
		else:
			orgs = WhoisManager(output, verbose).start()
		output = [(a+b) for a,b in zip(output, orgs)]

	return output

def createCSVheader():
	header = ['' for i in range(4)]
	header[0] = 'domain'
	header[1] = 'ip' if args.ip else ''
	header[2] = 'inetnum' if args.org else ''
	header[3] = 'org-name' if args.org else ''

	header = set(header)
	if '' in header:
			header.remove('')
	return ','.join(header)

def formatize(output):
	temp = list(output)
	for i in range(len(temp)):
		if temp[i] == 0 or len(temp[i]) == 0:
			temp[i] = ''
	if args.csv:
		temp = ",".join(temp)
	else:
		temp = " ".join(temp)

def main():
	domain = validate(args.domain)
	subdomains = work(domain)
	overall = merge(subdomains)
	overall = beautify(overall)
	overall = additionals(overall)

	with open(args.output, "w+") as f:
		if args.csv:
			f.write("%s\n" % createCSVheader())

		for entry in overall:
			f.write("%s\n" % formatize(entry))

	if args.strict:
		print("\nFinished. There are %d online hosts on subdomains for %s" % (len(overall), domain))
	else:
		print("\nFinished. There are %d subdomains for %s" % (len(overall), domain))

if __name__ == "__main__":
	print_banner()
	args = parser.parse_args()
	verbose = 0 if (args.v is None) else args.v
	main()
