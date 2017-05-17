#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import plistlib
import base64
import SocketServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseRequestHandler
from cStringIO import StringIO
from HTMLParser import HTMLParser
from OpenSSL import crypto, SSL
from pyasn1.type import univ, constraint, char, namedtype, tag
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
import fcntl
import struct
import binascii
import netifaces
import hashlib
import requests
import uuid
import ConfigParser
import signal
from ProxyRewrite import *

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001

class ProxyAPNHandler:
    input_list = []
    channel = {}
    cakey = 'ssl/ca.key'
    cacert = 'ssl/ca.crt'
    certkey = 'ssl/cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()
    certKey=None
    issuerCert=None
    issuerKey=None
    apnslogger = None


    def __init__(self, host, port):
        if ProxyRewrite.usejbca:
            self.cacert = 'ssl/jbca.crt'
            self.cakey = 'ssl/jbca.key'

        self.certKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.certkey, 'rt').read())
        self.issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacert, 'rt').read())
        self.issuerKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakey, 'rt').read())

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if ProxyRewrite.unique_log_dir:
            logdir = ("logs_%s" % ProxyRewrite.dev1info['SerialNumber'])
        else:
            logdir = "logs"
        self.apnslogger = open(("%s/APNS.log" % logdir), "ab")
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    print("Incoming connection!")
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    self.apnslogger.close()
                    break
                else:
                    # on_recv() always receives data from server
                    print("received %d bytes from server" % len(self.data))
                    self.on_recv()

    def extract_certs(self, data):
        certs = None
        index=0

        while 1:
            index = data.find("\x30\x82", index)
            if index < 0: break
            length = struct.unpack(">h", data[index+2:index+4])[0] + 5
            if length > len(data):
                print("Length of %d extends past end" % length)
                return
            print("index=%d, length=%d" % (index, length))
            certdata = data[index:index+length]
            if certs == None: certs = []
            certs.append(certdata)
            index = index + length
        return certs

    def on_accept(self):
        clientsock, clientaddr = self.server.accept()

        SO_ORIGINAL_DST = 80
        dst = clientsock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16) # Get the original destination IP before iptables redirect
        _, dst_port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB8x", dst)
        dst_ip = '%s.%s.%s.%s' % (ip1,ip2,ip3,ip4)
        #with self.lock:
        #    certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)

        peername = '%s:%s' % (clientsock.getpeername()[0], clientsock.getpeername()[1])
        print('Client %s -> %s:%s' % (peername, dst_ip, dst_port))

        with self.lock:
            certpath = ProxyRewrite.generate_cert(self.certdir, self.certKey, self.issuerCert, self.issuerKey, dst_ip, dst_port)

        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if ProxyRewrite.apnproxyssl:
            ssl._https_verify_certificates(enable=False)
            clientsock = ssl.wrap_socket(clientsock, keyfile=self.certkey, certfile=certpath, server_side=True, do_handshake_on_connect=False)
            self.forward = ssl.wrap_socket(self.forward, ca_certs="server_certs/courier.push.apple.com.crt")#, cert_reqs=ssl.CERT_OPTIONAL)
        try:
            self.forward.connect((dst_ip, dst_port))
        except Exception, e:
            print e
            self.forward = None

        if self.forward:
            print clientaddr, "has connected"

            #ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            #ssl_context.load_cert_chain(certfile=certpath, keyfile=self.certkey)
            #ssl_context.set_alpn_protocols(["apns-security-v2"])
            #clientsock.do_handshake()
            #self.forward.do_handshake()
            # now do a wrap_socket on the forwarding port
            self.input_list.append(clientsock)
            self.input_list.append(self.forward)
            self.channel[clientsock] = self.forward
            self.channel[self.forward] = clientsock
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        if self.apnslogger:
            self.apnslogger.write(data)
        # here we can parse and/or modify the data before send forward
        self.channel[self.s].send(data)
