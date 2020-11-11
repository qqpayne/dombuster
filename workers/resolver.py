import socket
from math import ceil
import time
from threading import Thread
from workers.config import *
from workers.timer import format_seconds


class Resolver(Thread):

    def __init__(self, url, output, index):
        Thread.__init__(self)
        self.url = url
        self.output = output
        self.index = index

    def run(self):
        try:
            ip = socket.gethostbyname(self.url)
        except:
            ip = 0
        self.output[self.index] = ip

class ResolveManager():

    def __init__(self, urls, verbose, start_time):
        self.urls = urls
        self.verbose = verbose
        self.start_time = start_time

    def start(self):
        if self.verbose > 0:
            print("%s Starting DNS scan to determine domains IP addresses" % format_seconds(time.time()-self.start_time))
            
        threadnum = len(self.urls)
        output = [0 for i in range(threadnum)]
        threads = [Resolver(self.urls[i], output, i) for i in range(threadnum)]

        batches = ceil(threadnum / SIMULTANEOUS_THREADS)

        for i in range(batches):

            for j in range(SIMULTANEOUS_THREADS):
                currNum = i*SIMULTANEOUS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].start()
                    if self.verbose > 1:
                        print("%s Started thread for resolving %dth url" % (format_seconds(time.time()-self.start_time), currNum))

            for j in range(SIMULTANEOUS_THREADS):
                currNum = i*SIMULTANEOUS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].join()

        if self.verbose > 0:
            print("%s Finished DNS scan" % format_seconds(time.time()-self.start_time))

        return output