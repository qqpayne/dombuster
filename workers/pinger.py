import subprocess
import time
from math import ceil
from threading import Thread
from workers.timer import format_seconds
from workers.config import *

class Pinger(Thread):

    def __init__(self, url, output):
        Thread.__init__(self)
        self.url = url
        self.output = output

    def run(self):
        isUp = self.ping(self.url)
        # we need to return blank entry or url to just use set.remove(url) if host is down
        result = '' if isUp else self.url
        self.output.append(result)

    def ping(self, url):
        try:
            response = subprocess.check_output(
                ['ping', '-c', '1', '-w', str(TIMEOUT), self.url],
                stderr=subprocess.STDOUT)
            hostUp = True
        except:
            hostUp = False

        return hostUp

class PingManager():

    def __init__(self, urls, verbose, start_time):
        self.urls = urls
        self.verbose = verbose
        self.start_time = start_time

    def start(self):
        if self.verbose > 0:
            print("%s Starting ping scan to determine if hosts is up" % format_seconds(time.time()-self.start_time))
            
        threadnum = len(self.urls)
        output = []
        threads = [Pinger(self.urls[i], output) for i in range(threadnum)]

        batches = ceil(threadnum / SIMULTANEOUS_THREADS)

        for i in range(batches):

            for j in range(SIMULTANEOUS_THREADS):
                currNum = i*SIMULTANEOUS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].start()
                    if self.verbose > 1:
                        print("%s Started thread for pinging %dth url" % (format_seconds(time.time()-self.start_time), currNum))

            for j in range(SIMULTANEOUS_THREADS):
                currNum = i*SIMULTANEOUS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].join()

        if self.verbose > 0:
            print("%s Finished ping scan" % format_seconds(time.time()-self.start_time))

        return set(output)


        