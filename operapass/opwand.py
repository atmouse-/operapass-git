#!/usr/bin/env python2


from __future__ import print_function 
import sys
import os
import platform
import struct
import hashlib

# Try to use m2crypto, this is *much* faster than the pure python pyDes, but
# not as portable
try:
    import M2Crypto
    fastdes = True
except ImportError:
    import pyDes
    print("M2Crypto module not found, falling back to pyDes. Note this is *much* slower!")
    fastdes = False

class pwRawData():
    """
    ---this is the Hex cryptoData
    key:
    data:
    """
    def __init__(self):
        self.size=0
        self.key=""
        self.data=""
        
class pwTextData():
    def __init__(self):
        self.key=""
        self.timestamp=""
        self.onurl=""
        self.action="" 
        self.unknow_url2="" # unuse
        self.domain=""
        self.other=[] # other urlinfo,didn't decrypto
        self.other2=[] # other urlinfo text 
    
        self.fldsinfo_len=20
        self.fldsinfo=""
        self.flds_count=0
        self.flds=[] # flds is encrypt data [(tag_id,[pwRawData,pwRawData]),]
        self.fields=[] # fields is readable text data [(tag_id,text),]

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
        #print(pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text))
        return pyDes.triple_des(key, pyDes.CBC, iv).decrypt(text)

def GetPrintable(text):
    printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
    return ''.join([ b for b in text if b in printable ])

def getSize(fp):
    return int("%d"%struct.unpack('>I',fp.read(4)))

def getBlockData(fp,length):
    if length==0:
        return None
    #print("length:",length,fp.tell())
    block=pwRawData()
    block.size=length
    print("block_size:",block.size,"pos:",fp.tell())
    size_key=getSize(fp)
    if size_key!=8 :
        print("!!!!warnings,size_key",size_key,"pos:",fp.tell())
    block.key=struct.unpack('>%ss' % size_key, fp.read(size_key))[0]
    size_data=getSize(fp)
    print("size_data",size_data,"pos:",fp.tell())
    block.data=struct.unpack('>%ss' % size_data, fp.read(size_data))[0]
    print(length,size_key,size_data,GetPrintable(DecryptBlock(block.key,block.data)))
    #print("end pos:::::",fp.tell())
    return block
        
def getData(filepath):
    # head

    ret=[]
    
    fsize=os.stat(filepath).st_size
    
    def parse_head(fp):
        """
        00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01

        00 00 00 38 00 00 00 08 F9 BF 8B FD A5 45 15 22 00 00 00 28 99 20 8B C6 37 C7 9F 8C B4 33 34 DC C3 8F CF 34 20 19 23 85 3E 74 99 76 57 3A 1A 4A F2 BE A5 6E 94 5A A8 A6 08 82 D3 FB
        01
        00 00 00 01
        00 00 00 00
        
        00 00 00 00
        00 00 00 40 00 00 00 08 6B FA 63 BC 8C 77 DF 09 00 00 00 30 E6 B4 D2 40 38 1C 05 04 D9 CB 41 18 62 65 67 97 E0 6D 46 F2 4B 86 75 40 D6 0E 37 24 95 20 E4 DA 56 10 6A F9 A1 64 68 D9 29 D2 C3 D4 81 30 B2 24
        00 00 00 00 
        00 00 00 00 
        00 00 00 00 
        00 00 00 00 

        00 00 00 00 
        00 00 00 00 
        00 00 00 00 
        00 00 00 00 
        00 00 00 00 
        00 00 00 00 

        /00 00 00 01 
        00
        00 00 00 38 00 00 00 08 1F E1 AA 29 43 B9 BB 71 00 00 00 28 08 BD 3E AD F7 EE 02 94 01 94 90 D6 CC 2F BA A7 60 DA 15 68 00 F7 98 26 21 69 D8 CE CB 3D 15 FA D8 51 3C 42 91 6A AD C9
        00 00 00 58 00 00 00 08 6C 97 6B 5D 9C 66 E7 34 00 00 00 48 B2 C0 50 85 15 8C B0 FB 94 E1 B9 0D DD 16 32 C7 AE 25 CA 2D C2 E6 09 B8 36 E1 05 8F 60 04 05 54 9F 75 31 38 C6 54 52 52 74 45 A6 DA 85 22 49 EF AE 69 EE A8 DE 06 64 03 93 83 50 A6 5C F5 C7 B2 92 D1 71 E9 B4 D9 DD F1
        00 00 00 00

        00 00 00 30 00 00 00 08 93 58 8F F7 AD A9 24 A1 00 00 00 20 49 6B 89 36 17 8B 97 80 44 61 73 E2 59 65 CD 20 3F 40 AC 95 E9 3C BA 4E F0 89 FD 0A 0C 57 7F B6
        """
        
        # unknow head info here!
        head_info={}
        start_pos=fp.read().find("\x00\x00\x00\x38\x00\x00\x00\x08\xF9\xBF\x8B\xFD\xA5\x45\x15\x22\x00\x00\x00\x28\x99\x20\x8B\xC6\x37\xC7\x9F\x8C\xB4\x33\x34\xDC\xC3\x8F\xCF\x34\x20\x19\x23\x85\x3E\x74\x99\x76\x57\x3A\x1A\x4A\xF2\xBE\xA5\x6E\x94\x5A\xA8\xA6\x08\x82\xD3\xFB")

        """
        01
        00 00 00 01
        00 00 00 00
        """
        fp.seek(start_pos+60)
        fp.read(9)
        
        print(fp.tell())
        
        # unkown
        for un in range(12):
            print("circle:",un)
            l=getSize(fp)
            if l:
                getBlockData(fp,l)
            
        # unkown fields, include wand.dat version
        c=getSize(fp)
        if c:
            read_fields(fp,c)
            head_info["version"]=9
        else:
            head_info["version"]=6
        
        # another unkown
        print(" Log profile")
        l=getSize(fp)
        if l:
            getBlockData(fp,l)
        
        fp.read(1)
        head_info["pw_count"]=getSize(fp)
        return head_info
        
    def read_fields(fp,count):
        if not count:
            return None
        ret=[]
        for i in xrange(count):
            tag_id=fp.read(1)
            #print("tag_id",ord(tag_id))
            d=[]
            for j in xrange(3):
                ## each tag_id with 3 block, including an empty block
                l=getSize(fp)
                if l<9 :
                    #print("ord(l)",l,fp.tell())
                    continue
                d.append(getBlockData(fp,l))
                #print("append data:",str(i)*3)
            ret.append((tag_id,d[:]))
        return ret
        
    with open(filepath,"rb") as fp:
        #print("start 0")
        head_info=parse_head(fp)

        pw_total=head_info["pw_count"]
        print("total",pw_total,"passwords")
        while 1:
            print('*'*50)
            pd=pwTextData()
            try:
                #print(fp.tell())
                fstruct=getSize(fp)
                #print(hex(fstruct))
                
                ## tagid 6 is the opera:encrypto info,i didn't resolve the data here
                ## so ,pass -_-!
                if fstruct==6:break 
                
                while fstruct<=24 or fstruct>=256 :
                    print(">> head parse pass",fstruct)
                    ## the start of area flag is "\x58"
                    ##print("fstruct error,pos",fp.tell(),hex(fstruct))
                    fstruct=getSize(fp)

                domain_info_count=1
                max_count=6
                spec=0
                #print("start")
                                
                l=fstruct
                # ID
                pd.key=getBlockData(fp,l)
                # TIMESTAMP
                l=getSize(fp)
                pd.timestamp=getBlockData(fp,l)
                # URL
                l=getSize(fp)
                pd.onurl=getBlockData(fp,l)
                
                # unknow url
                print(">>","other domain info")
                l=getSize(fp)
                pd.action=getBlockData(fp,l)
                if head_info["version"] > 8:
                    # unknow url2
                    l=getSize(fp)
                    pd.unknow_url2=getBlockData(fp,l)
                    # unknow url3
                    l=getSize(fp)
                    pd.domain=getBlockData(fp,l)

                pd.fldsinfo=fp.read(24)

                pd.flds_count=getSize(fp)
                print(">> with",pd.flds_count,"fields")
                if pd.flds_count:
                    pd.flds=read_fields(fp,pd.flds_count)

                ret.append(pd)
                #print("end")
                #print("stack here****",fp.tell())
            except:
                print("except,pos:",fp.tell())
                break

    #print("len ret:",len(ret))
    
    if ret:
        return ret
    print("read file error!")
        
def DecryptPwTextData(tdata):
    ## tdata is an instants of pwTextData
    def Decrypt(d):
        if type(d) == type("") or d == None:
            return d
        else:
            return GetPrintable(DecryptBlock(d.key,d.data))
    try:
        tdata.key=Decrypt(tdata.key)
        tdata.timestamp=Decrypt(tdata.timestamp)
        tdata.onurl=Decrypt(tdata.onurl)
        if tdata.action:
            tdata.action=Decrypt(tdata.action)
        if tdata.unknow_url2:
            tdata.unknow_url2=Decrypt(tdata.unknow_url2)
        if tdata.domain:
            tdata.domain=Decrypt(tdata.domain)
        if tdata.other:
            for dt in tdata.other:
                tdata.other2.append(Decrypt(dt))

        
        #tdata.fldsinfo_len=24
        #tdata.fldsinfo
        #tdata.flds_count

        for tag_id,pwrawdatas in tdata.flds:
            #print(struct.unpack("s",tag_id)[0])
            d_temp=[]
            d_temp.append(struct.unpack("s",tag_id)[0])
            for pwrdata in pwrawdatas:
                d_temp.append(Decrypt(pwrdata))
            tdata.fields.append(d_temp[:])
    except:
        print("decrypto error")

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
        print("Password file %s doesn't exist." % pwfile)
        sys.exit(1)

    return pwfile

def PrintTextData(pwdatas):
    print("*"*50)
    for pwdata in pwdatas:
        DecryptPwTextData(pwdata)
        print("ID:\t",pwdata.key)
        print("TIMESTAMP:\t",pwdata.timestamp)
        print("ONURL:\t",pwdata.onurl)
        print("ACTION:\t",pwdata.action)
        print("UNKNOW:\t",pwdata.unknow_url2)
        print("DOMAIN:\t",pwdata.domain)
        print("fields_info(24):\t",pwdata.fldsinfo.encode('hex'))
        if pwdata.other:
            print("otherUrlInfo:",pwdata.other2)
        
        #print(pwdata.fldsinfo_len)
        #print(pwdata.fldsinfo)
        print("data_fields_count",pwdata.flds_count)
        #print(pwdata.flds) # flds is encrypt data [(tag_id,[pwRawData,pwRawData,pwRawData]),]
        for i in pwdata.fields:
            print('\t',i) # fields is readable text data [(type,text),]
        print("")
        print("*"*50)
        print("")
