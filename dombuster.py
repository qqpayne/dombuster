#!/usr/bin/env python3
import re
import json
import argparse
import time
from workers.scrapers import *
from workers.resolver import *
from workers.pinger import *
from workers.whois import *
from banner import print_banner
from workers.timer import format_seconds

parser = argparse.ArgumentParser()
parser.add_argument('domain', type=str, help="Domain name to search for subdomains")
parser.add_argument('output', type=str, help="Name of output file")
parser.add_argument('-k', type=str, help="Path to JSON file with API keys. Currently only VirusTotal and SecurityTrail.")
parser.add_argument('-v', action="store_true", help="Verbosity (caution: it will probably flood your console)")
parser.add_argument('-q', action="store_true", help="Suppress console output")
parser.add_argument('-f', action="store_true", help="Don't use slow sources and go fast and furious")
parser.add_argument("--strict", action='store_true', help="Save only hosts that are online")
parser.add_argument("--ip", action='store_true', help="Save IP address of subdomain")
parser.add_argument("--org", action='store_true', help="Save OrgName and NetRange from reverse whois lookup on subdomain (can be kinda slow)")
parser.add_argument("--csv", action='store_true', help="Output in CSV (default: plaintext)")

APISources = [VirusTotal, SecurityTrails]

def validate(domain):
	try:
		# all sources accept kaspersky.com, not https://kaspersky.com
		validation = re.match(r"[^/]*\.[a-zA-Z]{2,}$", domain)
		if validation:
			return validation.group(0)
		else:
			print("%s is not a valid domain. Please enter valid one" % domain)
			exit(1)
	except:
		exit(1)

def work(domain):
	sources = [child for child in Scraper.__subclasses__() if child not in APISources]
	if args.f:
		# slow sources
		sources.remove(GoogleTransparency)
		sources.remove(Yahoo)
		sources.remove(Baidu)
		sources.remove(Google)
		sources.remove(DuckDuckGo)

	subdomains = [[] for i in range(len(sources))]
	threads = [sources[i](domain, subdomains[i], verbose, start_time) for i in range(len(sources))]
	if args.k:
		with open(args.k, "r") as f:
			keys = json.loads(f.read())

		for src in APISources:
			if str(src.__name__) in keys:
				if verbose > 0:
					print("%s Found %s key" % (format_seconds(time.time()-start_time), src.__name__))
				subdomains.append([])
				threads.append(src(domain, subdomains[len(subdomains)-1], verbose, start_time, keys[src.__name__]))

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
		offlineHosts = PingManager(list(output), verbose, start_time).start()
		output -= offlineHosts

	return output

def additionals(output):
	if args.ip:
		ips = ResolveManager(list(output), verbose, start_time).start()
		output = [(a,b) for a, b in zip(output, ips)]

	if args.org:
		if not args.ip:
			ips = ResolveManager(list(output), verbose, start_time).start()
			tuples = [(a,b) for a, b in zip(output, ips)]
			orgs = WhoisManager(tuples, verbose, start_time).start()
			output = [(a, '') for a in output]
		else:
			orgs = WhoisManager(output, verbose, start_time).start()
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
	if not args.ip and not args.org:
		return output

	temp = list(output)
	for i in range(len(temp)):
		if temp[i] == 0 or len(temp[i]) == 0 or temp[i] == 'dummy':
			temp[i] = ''
		else:
			temp[i] = ''.join(temp[i])

	if args.csv:
		temp = ",".join(temp)
	else:
		temp = " ".join(temp)
	return temp

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

	if verbose > 0:
		if args.strict:
			print("%s Search is over. There are %d online hosts on subdomains for %s" % (format_seconds(time.time()-start_time), len(overall), domain))
		else:
			print("%s Search is over. There are %d unique subdomains for %s" % (format_seconds(time.time()-start_time), len(overall), domain))

if __name__ == "__main__":
	args = parser.parse_args()
	if args.q and args.v:
		print("Conflicting arguments: -q and -v")
		exit(1)
	elif args.q:
		verbose = 0
	elif args.v:
		verbose = 2
	else:
		verbose = 1

	if verbose > 0:
		print_banner()

	start_time = time.time()
	main()
