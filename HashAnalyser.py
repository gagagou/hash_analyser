#!/usr/bin/python3
# -*- coding: utf-8 -*
import sys
import hashlib
import os
import datetime
import csv
import codecs
import time
import multiprocessing
from optparse import OptionParser

# sudo python3 HashAnalyser.py --scandir '/tmp/,/etc/'--blacklist '/home/chga/Bureau/AFTI/FORENSIC/WHITELIST/RDS_modern/NSRLFile.txt' --whitelist '/home/chga/Bureau/AFTI/FORENSIC/WHITELIST/RDS_modern/NSRLFile.txt'
# sudo python3 HashAnalyser.py --blacklist '/home/chga/Bureau/AFTI/FORENSIC/WHITELIST/RDS_modern/NSRLFile.txt' --whitelist '/home/chga/Bureau/AFTI/FORENSIC/WHITELIST/RDS_modern/NSRLFile.txt' --scandir '/'
parser = OptionParser()
parser.add_option("-w", "--whitelist", dest="WHITELIST",
                  help="WHITELIST FILE", metavar="WHITELIST")
parser.add_option("-b", "--blacklist", dest="BLACKLIST",
                  help="BLACKLIST FILE", metavar="BLACKLIST")
parser.add_option("-d", "--scandir", dest="SCAN_DIR",
                  help="SCAN DIR", metavar="SCAN_DIR")
(options, args) = parser.parse_args()

WHITELIST = options.WHITELIST
BLACKLIST = options.BLACKLIST
SCAN_DIR = list(s for s in options.SCAN_DIR.split(','))


UNKNOW=[]
UNKNOW_SHA1=set()
COUNTER=8000000
OUT_CSV_DELIMITER=','

CPUCOUNT=multiprocessing.cpu_count()
print (CPUCOUNT, 'CORES DETECTED')
NUMPROCESS=CPUCOUNT*2

#########################""

def sha256sum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def sha1sum(filename, block_size=65536):
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha1.update(block)
    return sha1.hexdigest()

def md5sum(filename, block_size=65536):
    md5sum = hashlib.md5()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            md5sum.update(block)
    return md5sum.hexdigest()

def check_whitelist_bloc(item, q):
    for line in item :
        check_whitelist_line(line, q)

def check_whitelist_line(line, q):
    # STR TO LIST
    line = line.replace('"', '')
    line = tuple(s for s in line.split(','))

    # SHA1 in UNKNOWS ?
    if line[0] not in UNKNOW_SHA1:
        return

    for unk in UNKNOW:
        # SHA1
        if line[0] != unk[5]:
            continue

        # MD5
        if line[1] != unk[4]:
            continue
        q.put(unk)

    return

def check_blacklist_bloc(item, q):
    for line in item :
        check_blacklist_line(line, q)

def check_blacklist_line(line, q):
    # STR TO LIST
    line = line.replace('"', '')
    line = tuple(s for s in line.split(','))

    # SHA1 in UNKNOWS ?
    if line[0] not in UNKNOW_SHA1:
        return

    for unk in UNKNOW:
        # SHA1
        if line[0] != unk[5]:
            continue

        # MD5
        if line[1] != unk[4]:
            continue
        q.put(unk)

    return


# Scan des fichiers
for DIR in SCAN_DIR:
    print('NOW SCANNING FOR FILES IN DIRECTORY :',DIR)
    for path, dirs, files in os.walk(DIR, followlinks=False):
        for filename in files:
            FILE = os.path.join(path, filename)
            #print(FILE)

            # Regular file ?
            if not os.path.isfile(FILE):
                continue

            # LINK ?
            if os.path.islink(FILE):
                continue

            #Date de derniere modification
            mtimestamp = os.path.getmtime(FILE)
            mtime = datetime.datetime.fromtimestamp(mtimestamp)

            #Taille du fichier
            size = os.path.getsize(FILE)

            md5 = md5sum(FILE)
            sha1 = sha1sum(FILE)
            sha256 = sha256sum(FILE)

            item = [filename, path, size, mtime, md5, sha1, sha256]

            UNKNOW.append(item)
            UNKNOW_SHA1.add(sha1)

# Lecture de la WHITELIST
print('NOW CHECKING FOR WHITELIST MATCH')
f = open(WHITELIST, 'r', encoding="utf-8", errors="ignore")
line = f.readline()
cpt = 0
ts = time.time()
buff=[]
processes = {}
q = multiprocessing.Queue()
while line or buff:
    buff.append(line)
    if cpt == COUNTER :
        while buff :
            for i in range(NUMPROCESS) :
                if len(processes) == NUMPROCESS and processes[i].is_alive() :
                    continue
                processes[i] = multiprocessing.Process(target=check_whitelist_bloc, args=(buff,q))
                processes[i].start()
                buff=[]
                break
            time.sleep(0.1)
        cpt = 0
        old_ts = ts
        ts = time.time()
        delay = ts - old_ts
        if line:
            print ('~',int(COUNTER/delay/1000),'Mille Lignes / Seconde (WHITELIST)')
    cpt += 1
    line = f.readline()
    if not line :
        cpt = COUNTER
f.close()
for k,v in processes.items():
    processes[k].join()

LEGIT=[]
while not q.empty():
    info = q.get()
    LEGIT.append(info)


# Retrait de LEGIT de UNKNOW
for item in LEGIT:
    if item in UNKNOW:
        UNKNOW.remove(item)

# Création CSV LEGIT
with open(r'legit.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=OUT_CSV_DELIMITER)
    writer.writerows(LEGIT)
LEGIT=""

# Lecture de la BLACKLIST
print('NOW CHECKING FOR BLACKLIST MATCH')
f = open(BLACKLIST, 'r', encoding="utf-8", errors="ignore")
line = f.readline()
cpt = 0
ts = time.time()
buff=[]
processes = {}
q = multiprocessing.Queue()
while line or buff:
    buff.append(line)
    if cpt == COUNTER :
        while buff :
            for i in range(NUMPROCESS) :
                if len(processes) == NUMPROCESS and processes[i].is_alive() :
                    continue
                processes[i] = multiprocessing.Process(target=check_blacklist_bloc, args=(buff,q))
                processes[i].start()
                buff=[]
                break
            time.sleep(0.1)
        cpt = 0
        old_ts = ts
        ts = time.time()
        delay = ts - old_ts
        if line:
            print ('~',int(COUNTER/delay/1000),'Mille Lignes / Seconde (BLACKLIST)')
    cpt += 1
    line = f.readline()
    if not line :
        cpt = COUNTER
f.close()
for k,v in processes.items():
    processes[k].join()

MALICIOUS=[]
while not q.empty():
    info = q.get()
    MALICIOUS.append(info)

# Retrait de MALICIOUS de UNKNOW
for item in MALICIOUS:
    if item in UNKNOW:
        UNKNOW.remove(item)

# Création CSV MALICIOUS
with open(r'malicious.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=OUT_CSV_DELIMITER)
    writer.writerows(MALICIOUS)

# Création CSV UNKNOW
with open(r'unknow.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=OUT_CSV_DELIMITER)
    writer.writerows(UNKNOW)

print('SCAN COMPLETE')
