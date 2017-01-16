#!/usr/bin/python2.7

import socket
import fcntl
import struct
import sqlite3 as lite
import sys

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])



class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''

    tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.domain+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def answer(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

if __name__ == '__main__':
  ip=get_ip_address('wlp61s0')
  print 'DNS Server %s' % ip
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  try:
    con = lite.connect('dns.db')
    cur = con.cursor()
    cur.executescript("""
        DROP TABLE IF EXISTS DNS;
        CREATE TABLE DNS(
            Hostname TEXT,
            Address TEXT,
            unique(Hostname)
        );
        """)
    con.commit()

    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      address = socket.gethostbyname(p.domain)
      con.execute("INSERT INTO DNS VALUES('"+p.domain+"','"+address+"');")
      con.commit()
      udps.sendto(p.answer(ip), addr)
      print 'Answer: %s -> %s' % (p.domain, address)

  except KeyboardInterrupt:
    if con: con.close()
    udps.close()

