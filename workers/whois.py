import subprocess
import re
import time
from collections import deque
from workers.timer import format_seconds

class WhoisManager():

    def __init__(self, tuples, verbose, start_time):
        self.tuples = tuples
        self.verbose = verbose
        self.start_time = start_time
        self.q = deque()
        for elem in self.tuples:
            self.q.append(elem)

    def resolveWhoIs(self, ip):
        if not re.match(r"[\d\.]{3}\d+", str(ip)):
            return "dummy"
        cmd = ['whois', ip]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        return proc.stdout.read().decode('utf-8')
        
    def parseWhoIs(self, output):
        try:
            org = re.findall(r"\norg-name:\s+([\w\s]+)\n", output)
        except:
            org = 'dummy'

        try:
            netnum = re.findall(r"\ninetnum:\s+([\d.]+ - [\d.]+)\n", output)
        except:
            netnum = 'dummy'

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
        if self.verbose > 0:
            print("%s Starting whois resolvation" % format_seconds(time.time()-self.start_time))
            
        knownIPs = []
        output = []
        while self.q:
            current = self.q.popleft() 
            # starting from the left end, because we need output be consistent with input
            for i in range(len(knownIPs)):
                if self.checkIPrange(knownIPs[i][0], current[1]):
                    if self.verbose > 1:
                        print("%s Hit in whois cache for %s" % (format_seconds(time.time()-self.start_time),current[0]))
                    output.append(knownIPs[i])
                    continue
            result = self.resolveWhoIs(current[1])
            parsedTuple = self.parseWhoIs(result)
            if parsedTuple not in knownIPs and len(parsedTuple) == 2 and len(parsedTuple[0]) > 0 and len(parsedTuple[1]) > 0: 
                knownIPs.append(parsedTuple)
            output.append(parsedTuple)

        if self.verbose > 0:
            print("%s Finished whois resolvation" % format_seconds(time.time()-self.start_time))

        return output




