import socket
from math import ceil
from threading import Thread
from workers.config import *

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

    def __init__(self, urls, verbose):
        self.urls = urls
        self.verbose = verbose

    def start(self):
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
                        print("Started thread for resolving %dth url" % (currNum))

            for j in range(SIMULTANEOUS_THREADS):
                currNum = i*SIMULTANEOUS_THREADS+j
                if currNum < threadnum:
                    threads[currNum].join()

        return output