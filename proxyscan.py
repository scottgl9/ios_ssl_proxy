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
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from HTMLParser import HTMLParser
from OpenSSL import crypto
import fcntl
import struct
import binascii

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

# Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, MKCOL, MOVE, REPORT, PROPFIND, PROPPATCH, ORDERPATCH

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    # lets use IPv4 instead of IPv6
    #address_family = socket.AF_INET6
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRewrite:
    dev1info = dict()
    logger = None

    @staticmethod
    def load_device_info(sn):
        device = plistlib.readPlist("devices/%s.xml" % sn)
        return device

    @staticmethod
    def intercept_this_host(hostname):
        if "apple.com" not in hostname and "icloud.com" not in hostname: return False
        if hostname == "gsa.apple.com": return False
        if hostname == "ppq.apple.com": return False
        if hostname == "albert.apple.com": return False
        if hostname == "static.ips.apple.com": return False
        #if hostname == "gsas.apple.com": return False
        #if hostname == "gspe1-ssl.ls.apple.com:": return False
        #if hostname == "gsp10-ssl.apple.com": return False
        #if hostname == "init.itunes.apple.com": return False
        #if hostname == "profile.ess.apple.com": return False
        #if hostname == "xp.apple.com": return False
        #if hostname == "itunes.apple.com": return False
        #if hostname == "p59-escrowproxy.icloud.com": return False
        #if hostname == "p59-ckdatabase.icloud.com": return False
        #if hostname == "p57-escrowproxy.icloud.com": return False
        #if hostname == "p57-ckdatabase.icloud.com": return False
        #if hostname == "p51-escrowproxy.icloud.com": return False
        #if hostname == "p51-ckdatabase.icloud.com": return False
        #if hostname == "p15-escrowproxy.icloud.com": return False
        #if hostname == "p15-ckdatabase.icloud.com": return False
        return True

    @staticmethod
    def scan_headers_attribs(headers, attribs):
        attriblist = attribs.split(',')
        for attrib in attriblist:
            for (key, value) in headers.items():
                if str(ProxyRewrite.dev1info[attrib]) in value:
                    print("%s: %s" % (key, value))

    @staticmethod
    def scan_headers_attrib_binary_b64(headers, attrib):
        binstr = binascii.unhexlify(ProxyRewrite.dev1info[attrib])
        encoded_data = base64.b64encode(binstr).replace('=', '')

        for (key, value) in headers.items():
            if encoded_data in value:
                print("%s: %s" % (key, value))

    @staticmethod
    def scan_body_attribs(body, attribs, hostname):
        if body == None: return
        attriblist = attribs.split(',')
        for attrib in attriblist:
            if str(ProxyRewrite.dev1info[attrib]) in body:
                print('Host: %s (%s)' % (hostname, attrib))
                print(str(body))
                return

    @staticmethod
    def scan_body_attrib_binary(body, attrib, hostname):
        if body == None: return
        binstr = binascii.unhexlify(ProxyRewrite.dev1info[attrib])
        encoded_data = base64.b64encode(binstr).replace('=', '')

        if binstr in body:
            print('Host: %s (%s)' % (hostname, attrib))
            print(str(body))
            return
        if encoded_data in body:
            print('Host: %s (%s)' % (hostname, attrib))
            print(str(body))
            return


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()
    certKey=None
    issuerCert=None
    issuerKey=None

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        self.certKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.certkey, 'rt').read())
        self.issuerCert=crypto.load_certificate(crypto.FILETYPE_PEM, open(self.cacert, 'rt').read())
        self.issuerKey=crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.cakey, 'rt').read())

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    # hack to handle so that we can ignore certain hostnames
    def handle(self):
        SO_ORIGINAL_DST = 80
	dst = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16) # Get the original destination IP before iptables redirect
	_, dst_port, ip1, ip2, ip3, ip4 = struct.unpack("!HHBBBB8x", dst)
	dst_ip = '%s.%s.%s.%s' % (ip1,ip2,ip3,ip4)
	peername = '%s:%s' % (self.request.getpeername()[0], self.request.getpeername()[1])
        """Handle multiple requests if necessary."""
        self.close_connection = 1
        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def do_CONNECT(self):
        hostname = self.path.split(':')[0]
        if 'Proxy-Connection' in self.headers:
            del self.headers['Proxy-Connection']

        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir) and ProxyRewrite.intercept_this_host(hostname):
            self.connect_intercept()
        else:
            print(self.headers)
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                req = crypto.X509Req()
                req.get_subject().CN = hostname
                req.set_pubkey(self.certKey)
                req.sign(self.certKey, "sha1")
                epoch = int(time.time() * 1000)
                cert = crypto.X509()
                cert.set_serial_number(epoch)
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(60 * 60 * 24 * 3650)
                cert.set_issuer(self.issuerCert.get_subject())
                cert.set_subject(req.get_subject())
                cert.set_pubkey(req.get_pubkey())
                cert.sign(self.issuerKey, "sha256")
                with open(certpath, "w") as cert_file:
                    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        try:
            self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True, do_handshake_on_connect=False) #suppress_ragged_eofs=True)
        except ssl.SSLEOFError as e:
            print("SSLEOFError occurred on "+self.path)
            self.finish()

        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        if 'Proxy-Connection' in self.headers:
            del self.headers['Proxy-Connection']

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control'):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
                #self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET

    # handle all weird http requests used by apple servers
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_MKCOL = do_GET
    do_MOVE = do_GET
    do_REPORT = do_GET
    do_PROPFIND = do_GET
    do_PROPPATCH = do_GET
    do_ORDERPATCH = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade', 'Proxy-Connection')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        if ProxyRewrite.dev1info == None:
            return

        ProxyRewrite.scan_headers_attribs(req.headers,'BasebandMasterKeyHash,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress')
        #ProxyRewrite.scan_headers_attribs(req.headers,'BuildVersion,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,ProductVersion,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress')
        ProxyRewrite.scan_headers_attrib_binary_b64(req.headers, 'UniqueDeviceID')
        ProxyRewrite.scan_headers_attrib_binary_b64(req.headers, 'DeviceGUID')
        ProxyRewrite.scan_headers_attrib_binary_b64(req.headers, 'BasebandMasterKeyHash')

        hostname = ''
        if 'Host' in req.headers:
            hostname = req.headers['Host']

        ProxyRewrite.scan_body_attribs(req_body, 'BasebandMasterKeyHash,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress', hostname)
        #ProxyRewrite.scan_body_attribs(req_body, 'BuildVersion,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,ProductVersion,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress', hostname)

        ProxyRewrite.scan_body_attrib_binary(req_body, 'UniqueDeviceID', hostname)
        ProxyRewrite.scan_body_attrib_binary(req_body, 'DeviceGUID', hostname)
        ProxyRewrite.scan_body_attrib_binary(req.headers, 'BasebandMasterKeyHash', hostname)


    def response_handler(self, req, req_body, res, res_body):
        ProxyRewrite.scan_headers_attribs(res.headers,'BuildVersion,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,ProductVersion,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress')
        ProxyRewrite.scan_headers_attrib_binary_b64(req.headers, 'UniqueDeviceID')
        ProxyRewrite.scan_headers_attrib_binary_b64(req.headers, 'DeviceGUID')

        hostname = ''
        if 'Host' in req.headers:
            hostname = req.headers['Host']

        ProxyRewrite.scan_body_attribs(res_body, 'DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress', hostname)
        #ProxyRewrite.scan_body_attribs(res_body, 'BuildVersion,DeviceColor,DeviceGUID,DieID,EnclosureColor,EthernetAddress,FirmwareVersion,HardwareModel,HardwarePlatform,InternationalMobileEquipmentIdentity,MLBSerialNumber,MobileEquipmentIdentifier,ModelNumber,ProductType,ProductVersion,SerialNumber,TotalDiskCapacity,UniqueChipID,UniqueDeviceID,WiFiAddress', hostname)
        ProxyRewrite.scan_body_attrib_binary(res_body, 'UniqueDeviceID', hostname)
        ProxyRewrite.scan_body_attrib_binary(res_body, 'DeviceGUID', hostname)


    def save_handler(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s" % (req.command, req.path, req.request_version)

        print with_color(33, req_header_text)

        hostname = ''
        if 'Host' in req.headers:
            hostname = req.headers['Host']

        ProxyRewrite.logger = open(hostname+".log", "ab")
        ProxyRewrite.logger.write(str(self.command+' '+self.path+"\n"))
        ProxyRewrite.logger.write(str(req.headers))
        ProxyRewrite.logger.write(str(req_body))
        ProxyRewrite.logger.write(str(res.headers))
        ProxyRewrite.logger.write(str(res_body))
        ProxyRewrite.logger.close()

def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[2:]:
        port = int(sys.argv[1])
        device1 = sys.argv[2]

    else:
        print("Usage: %s <port> <device>" % sys.argv[0])
        return 0

    print("Proxy set to scan for device %s" % (device1))
    ProxyRewrite.dev1info = ProxyRewrite.load_device_info(device1)

    #server_address = (get_ip_address('wlp61s0'), port)
    server_address = (get_ip_address('wlo1'), port)

    try:
        HandlerClass.protocol_version = protocol
        httpd = ServerClass(server_address, HandlerClass)
        httpd.allow_reuse_address = True
        httpd.request_queue_size = 256

        sa = httpd.socket.getsockname()
        print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
        httpd.serve_forever()

    except KeyboardInterrupt:
        print '^C received, shutting down proxy'
        httpd.socket.close()


if __name__ == '__main__':
    test()
