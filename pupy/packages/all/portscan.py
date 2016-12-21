#!/usr/bin/env python
import socket
import sys
import threading
import Queue

open_port = []

class WorkerThread(threading.Thread) :

    def __init__(self, queue, tid, remote_ip, ports, settimeout) :
        threading.Thread.__init__(self)
        self.queue = queue
        self.tid = tid
        self.ports = ports
        self.remote_ip = remote_ip
        self.timeout = settimeout

    def check_open_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((self.remote_ip, port))
        if result == 0:
            sock.close()
            open_port.append(port)

    def run(self):
        for port in self.ports:
            try :
                port = self.queue.get(timeout=1)
            except Queue.Empty :
                return
            self.check_open_port(port)
            self.queue.task_done()

def scan(remote_ip, ports, nb_threads, settimeout):
    global open_port
    open_port = []
    
    queue = Queue.Queue()
    threads = []

    for i in range(1, nb_threads):
        worker = WorkerThread(queue, i, remote_ip, ports, settimeout) 
        worker.setDaemon(True)
        worker.start()
        threads.append(worker)
        
    for j in ports:
        queue.put(j)

    queue.join()

    # wait for all threads to exit 
    for item in threads :
        item.join()

    return open_port