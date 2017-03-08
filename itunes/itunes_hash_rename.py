#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# script to rename files from an iOS itunes backup to their correct names

import sys
import os
import sqlite3 as lite

if sys.argv[3:]:
    hashmap = sys.argv[1]
    path = sys.argv[2]
    dpath = sys.argv[3]

else:
    print("Usage: %s <hashmap> <backup path> <destination path>" % sys.argv[0])
    exit(0)
    
def traverse(a, hashdict):
    for item in os.listdir(a):
        fullpath=os.path.join(a,item)
        if os.path.isfile(fullpath) and item in hashdict:
            filesize = os.stat(fullpath).st_size
            if (filesize > 42): print("%s -> %s %d" % (item, hashdict[item], filesize))
        elif os.path.isdir(fullpath):
            traverse(fullpath, hashdict)

def load_hashmap(path):
    hashdict = dict()
    with open(path) as file_:
        for line in file_:
            line = line.rstrip('\n')
            parts = line.split(' ')
            hashdict[parts[0]] = parts[1]
    return hashdict

def load_manifest(path):
    try:
        con = lite.connect(path+"/Manifest.db")
        cur = con.cursor()
        cur.execute('SELECT * from files')
        data = cur.fetchone()
        print(data)
    except lite.Error, e:
        print "Error %s:" % e.args[0]

def remove_file_from_backup(path, filename):
    fullpath = "%s/%s/%s" % (path, filename[0:2], filename)
    print(fullpath)
    if os.path.isfile(fullpath) == None: return
    try:
        con = lite.connect(path+"/Manifest.db")
        cur = con.cursor()
        cur.execute("SELECT * from files WHERE fileID='"+filename+"'")
        data = cur.fetchone()
        print(data)
    except lite.Error, e:
        print "Error %s:" % e.args[0]

hashdict = load_hashmap(hashmap)
traverse(path, hashdict)
load_manifest(path)
remove_file_from_backup(path, "3d0d7e5fb2ce288813306e4d4636395e047a3d28") 
