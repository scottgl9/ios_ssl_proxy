#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# script to rename files from an iOS itunes backup to their correct names

import sys
import os

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
            print("%s -> %s" % (item, hashdict[item]))
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

hashdict = load_hashmap(hashmap)
traverse(path, hashdict)
