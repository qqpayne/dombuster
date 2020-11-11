import subprocess
import re
from collections import deque

class WhoisManager():

    def __init__(self, tuples, verbose):
        self.tuples = tuples
        self.verbose = verbose
        self.q = deque()
        for elem in self.tuples:
            self.q.append(elem)

    def resolveWhoIs(self, ip):
        if not re.match(r"[\d\.]{3}\d+", str(ip)):
            return ""
        cmd = ['whois', ip]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        return proc.stdout.read().decode('utf-8')
        
    def parseWhoIs(self, output):
        try:
            org = re.findall(r"\norg-name:\s+([\w\s]+)\n", output)
        except:
            org = ''

        try:
            netnum = re.findall(r"\ninetnum:\s+([\d.]+ - [\d.]+)\n", output)
        except:
            netnum = '0'

        return (netnum, org)

    def checkIPrange(self, rangeIP, targetIP):
        try:
            rangeIP = rangeIP.split("-")
            start = rangeIP[0]
            end = rangeIP[1]
        except:
            return False
        return self.parseIP4(start) < self.parseIP4(targetIP) < self.parseIP4(end)

    def parseIP4(self, ip):
        return tuple(int(n) for n in ip.split('.'))

    def start(self):
        knownIPs = []
        output = []
        while self.q:
            current = self.q.popleft() 
            # starting from the left end, because we need output be consistent with input
            for i in range(len(knownIPs)):
                if self.checkIPrange(knownIPs[i][0], current[1]):
                    if self.verbose > 1:
                        print("Hit in WhoIs cache for %s" % current[0])
                    output.append(knownIPs[i])
                    continue
            result = self.resolveWhoIs(current[1])
            parsedTuple = self.parseWhoIs(result)
            if parsedTuple not in knownIPs and len(parsedTuple) == 2 and len(parsedTuple[0]) > 0 and len(parsedTuple[1]) > 0: 
                knownIPs.append(parsedTuple)
            output.append(parsedTuple)

        return output




