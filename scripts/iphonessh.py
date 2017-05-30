#!/usr/bin/python

import paramiko
import re
import sys
import time
from paramiko.ssh_exception import SSHException, ChannelException
from subprocess import check_output, CalledProcessError

IPHONE_ADDR='192.168.12.249'

# execute long running command and print live output
def exec_long_command(ssh, command):
    sleeptime = 0.001
    outdata, errdata = '', ''
    newoutdata, newerrdata = '', ''
    ssh_transp = ssh.get_transport()
    chan = ssh_transp.open_session()
    chan.setblocking(0)
    chan.exec_command(command)
    while True:
        newoutdata, newerrdata = '', ''
        while chan.recv_ready():
            newoutdata += chan.recv(1024)
        while chan.recv_stderr_ready():
            newerrdata += chan.recv_stderr(1024)
        if newoutdata != '':
            for line in newoutdata.split('\n'):
                if line != '': print("\t%s" % line.strip('\n'))
            outdata += newoutdata
        if newerrdata != '':
            print(newerrdata)
            errdata += newerrdata
        if chan.exit_status_ready():
            break
        time.sleep(sleeptime)
    retcode = chan.recv_exit_status()

def getPID(ssh, name, verbose=True):
    try:
        stdin, stdout, stderr = ssh.exec_command("pidof " + name)
        line = stdout.readline().strip('\n')
        if verbose == True:
		if line != '': return "\t%s running (pid=%s)" % (name, line)
		else: return "\t%s not running" % name
	else:
		return line
    except  CalledProcessError:
        return ''

def filePathExists(ssh, path):
    stdin, stdout, stderr = ssh.exec_command("if test -f %s; then echo 'true'; else echo 'false'; fi" % (path))
    if 'true' in stdout.readline().strip(): return True
    return False

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IPHONE_ADDR, username='root', password='alpine')
local_addr = (IPHONE_ADDR, 22)
vmtransport = ssh.get_transport()

paramiko.util.log_to_file("output.log")
stdin, stdout, stderr = ssh.exec_command("hostname")
hostname = stdout.readline().replace('\n','')
print(hostname)

vmtransport.close()
ssh.close()
