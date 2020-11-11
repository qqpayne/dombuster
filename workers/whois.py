import subprocess
import re
from math import ceil
import time
from threading import Thread
from workers.timer import format_seconds
from workers.config import *

class Whois(Thread):

    def __init__(self, ip, output, index):
        Thread.__init__(self)
        self.ip = ip
        self.output = output
        self.index = index

    def run(self):
        output = self.resolveWhoIs(self.ip)
        info = self.parseWhoIs(output)
        self.output[self.index] = info

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

class WhoisManager():

    def __init__(self, tuples, verbose, start_time):
        self.tuples = tuples
        self.verbose = verbose
        self.start_time = start_time


    def start(self):
        if self.verbose > 0:
            print("%s Starting whois resolvation" % format_seconds(time.time()-self.start_time))
            
        threadnum = len(self.tuples)
        output = [0 for i in range(threadnum)]
        threads = [Whois(self.tuples[i][1], output, i) for i in range(threadnum)]

        batches = ceil(threadnum / WHOIS_THREADS)

        for i in range(batches):

            for j in range(WHOIS_THREADS):
                currNum = i*WHOIS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].start()
                    if self.verbose > 1:
                        print("%s Started thread for resolving %dth url" % (format_seconds(time.time()-self.start_time), currNum))

            for j in range(WHOIS_THREADS):
                currNum = i*WHOIS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].join()

        if self.verbose > 0:
            print("%s Finished whois resolvation" % format_seconds(time.time()-self.start_time))

        return output




