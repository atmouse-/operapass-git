#!/usr/bin/env python
#
# Marin Tournoij <martin@arp242> 
# atmouse <github.com/atmouse->
#
# Free for any use, there are no restrictions
#
# This is, in part, based on the information found here:
#   http://securityxploded.com/operapasswordsecrets.php
#

import datetime
import hashlib
import os
import platform
import re
import struct
import sys

# Try to use m2crypto, this is *much* faster than the pure python pyDes, but
# not as portable
try:
    import M2Crypto
    fastdes = True
except ImportError:
    import pyDes
    print "M2Crypto module not found, falling back to pyDes. Note this is *much* slower!"
    fastdes = False

def DecryptBlock(key, text):
    # Static salt
    salt = '\x83\x7D\xFC\x0F\x8E\xB3\xE8\x69\x73\xAF\xFF'

    # Master password notes:
    #
    # This *only* encrypts pasword fields, not username/etc.  fields.
    # According to http://nontroppo.org/test/Op7/FAQ/opera-users.html#wand-security
    # "if you do use a master password, the used password is a combination of the
    # master password and a 128-byte random portion created at the same time.
    # This random portion is stored outside wand.dat, also encrypted with the
    # master password."
    # Random portion mentioned seems to be opcert6.dat
    #
    # According to http://my.opera.com/community/forums/topic.dml?id=132880
    # "opcert6.dat contains all private keys you have created and the associated
    # client certificates you have requested and installed. The private keys are
    # protected by the security password. [...] A small block of data in the
    # opcert6.dat file is also used when you secure the wand and mail passwords
    # with the security password."

    h = hashlib.md5(salt + key).digest()
    h2 = hashlib.md5(h + salt + key).digest()

    key = h[:16] + h2[:8]
    iv = h2[-8:]

    if fastdes:
        return M2Crypto.EVP.Cipher(alg='des_ede3_cbc', key=key, iv=iv, op=0,
            padding=0).update(text)
    else:
        print pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text)
        return pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text)

def GetPrintable(text):
    printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
    return ''.join([ b for b in text if b in printable ])

def GetData(pwfile):
    fsize = os.stat(pwfile).st_size

    with open(pwfile, 'rb') as fp:
        # Header, mostly 0. On my systems (FreeBSD&Win/11.51) 0x3 is set to 0x06, 0x23 to 0x01
        # If offset 0x07 is set to 1, is seems to flag that a master pw is set
        # TODO ^ Verify this, add detection
        data = fp.read(36)

        ret = []
        data = fp.read(4)
        while True:
            if len(data) < 4:
                # Nowhere near the end, assume "overlapping" of data
                if fsize - fp.tell() > 30:
                    diff = 4 - len(data)
                    #fp.seek(fp.tell() - diff)
                    data = ('\x00' * diff) + data
                else:
                    #print 'ret at line 57'
                    #print fp.tell()
                    return ret

            try:
                before = fp.tell()
                size_block = struct.unpack('>I', data)[0]
                size_key = struct.unpack('>I', fp.read(4))[0]
                key = struct.unpack('>%ss' % size_key, fp.read(size_key))[0]
                size_data = struct.unpack('>I', fp.read(4))[0]
                #print hex(size_data)
                data = struct.unpack('>%ss' % size_data, fp.read(size_data))[0]

                ret.append([key, data])
            except:
                #print 'passing...', fp.tell()
                fp.seek(before)
                pass

            # There often (but not always) seems to be some amount of zero-padding
            # after this ... The value is often "odd" such as uneven numbers and I
            # can't find a pattern ... This seems to skip/read over it without too
            # much problems ...
            n = []
            while True:
                d = fp.read(1)
                #print hex(ord(d)),

                if not d:
                    #print 'ret at line 80'
                    #print fp.tell()
                    return ret
                n.append(d)

                if d != '' and ord(d) != 255 and ord(d) > 8:
                    # Peek 4 bytes ahead, the key lenght is always 8 so we can use this
                    # to verify we've got the right number
                    pos = fp.tell()
                    check = fp.read(4)
                    if len(check) < 4:
                        return ret
                    fp.seek(pos)
                    #if (ord(check[3:4]) == 8):
                    #print '__', ord(check[0:1]), '__',
                    #print '__', ord(check[1:2]), '__',
                    #print '__', ord(check[2:3]), '__',
                    #print '__', ord(check[3:4]), '__'
                    if (ord(check[0:1]) == 0 and ord(check[1:2]) == 0
                            and ord(check[2:3]) == 0 and ord(check[3:4]) == 8):
                        data = ''.join(n[-4:])
                        #print 'BR %s, %s\n' % (fp.tell(), len(ret))
                        break

def GetPasswordfile():
    if len(sys.argv) > 1:
        pwfile = sys.argv[1]
    else:
        if sys.platform[:3] == 'win':
            # Windows Vista, 7
            if int(platform.version()[:1]) > 5:
                pwfile = os.path.expanduser('~/AppData/Roaming/Opera/Opera/wand.dat')
            # Windows XP, 2000
            else:
                pwfile = os.path.expanduser('~/Application Data/Opera/Opera/wand.dat')
        # UNIX-like and Linux systems
        else:
            pwfile = os.path.expanduser('~/.opera/wand.dat')

    if not os.path.exists(pwfile):
        print "Password file %s doesn't exist." % pwfile
        sys.exit(1)

    return pwfile

def GetPasswords(pwfile):
    """
        row = {"key":'',
        "time":'',
        "url":'',
        "field":[]
        }
    
    """
    # Bug here, I can't find a new to parse the format of the data 
    # list, It must read from the bin data ,then the hex flag will 
    # be the fixed way. --atmouse
    data = GetData(pwfile)
    rows = []
    key = None

    data_list=[]
    pflag=0
    for key, d in data:
        block = DecryptBlock(key, d)
        # Strip non-printable characters
        # XXX This also strips non-ASCII characters
        block = GetPrintable(block)
        print block
        if pflag==0:
            if block=="Log profile":pflag=1
        else:
            data_list.append(block)
        
    #data_list=data_list.split("Log profile")[1]
    if not data_list:
        print "error!"
        sys.exit()
        
    pos=1
    row = {"key":'',
        "time":'',
        "url":'',
        "field":[]
        }
    for i,data in enumerate(data_list):
        if not (len(data)==32 and data.isalnum() and data.isupper()):
            pos+=1
            if pos<=3:
                if pos==2:
                    row["time"]=data
                elif pos==3:
                    row["url"]=data
            else:
                row["field"].append(data)
            continue
        else:
            if i==0:
                row["key"]=data
                continue
            else:
                rows.append(row)
                row= {"field":[]}
                pos=1
            row["key"]=data

    return rows

def GetPasswordsDict(pwfile):
    passwords = GetPasswords(pwfile)
    ret = []
    for pw in passwords:
        try:
            pw["url"]
            pw["field"]
        except:
            print "bug err"
            continue

        dictrow = {
            # url bug
            'url': pw['url'],
            'time':pw['time'],
            'fields': {}
        }

        if len(pw["field"]) %2==0:
            data=pw["field"]
        else:
            dictrow["fields"]["unknow"]=pw['field'][0]
            data=pw["field"][1:]
        i=0
        for col in data:
            if i%2==0:
                key=col
            else:
                dictrow["fields"][key]=col
            i+=1

        ret.append(dictrow)
    return ret
