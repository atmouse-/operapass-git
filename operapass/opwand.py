#!/usr/bin/env python2


from __future__ import print_function 
import sys,os,platform
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
        self.unknow_url="" #unuse
        self.domain="" #unuse
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

def getBlockData(fp,length):
    
    #print("length:",length,fp.tell())
    block=pwRawData()
    block.size=length
    #print("block_size:pos:",fp.tell())
    
    #if block.size==0:
        #if typeBlock==2:n=fp.read(4);print(fp.tell(),"typeBlock"," 00 00 00 00 00 00 00 00");return "\x00\x00\x00\x00\x00\x00\x00\x00"
        #if typeBlock==1:print(fp.tell(),"typeBlock"," 00 00 00 00");return "\x00\x00\x00\x00"
    #print("read pos:",fp.tell())
    size_key=int("%d"%struct.unpack('>I',fp.read(4)))
    #if size_key==0:print("pos:",fp.tell(),"error")
    block.key=struct.unpack('>%ss' % size_key, fp.read(size_key))[0]
    size_data=int("%d"%struct.unpack('>I',fp.read(4)))
    block.data=struct.unpack('>%ss' % size_data, fp.read(size_data))[0]
    #print(length,size_key,size_data,GetPrintable(DecryptBlock(block.key,block.data)))
    #print("end pos:::::",fp.tell())
    return block
        
def getData(filepath):
    ret=[]
    
    fsize=os.stat(filepath).st_size
    with open(filepath,"rb") as fp:
        #print("start 0")
        start_pos=fp.read().find("\x00\x00\x00\x30\x00\x00\x00\x08\x93\x58\x8F\xF7\xAD\xA9\x24\xA1\x00\x00\x00\x20\x49\x6B\x89\x36\x17\x8B\x97\x80\x44\x61\x73\xE2\x59\x65\xCD\x20\x3F\x40\xAC\x95\xE9\x3C\xBA\x4E\xF0\x89\xFD\x0A\x0C\x57\x7F\xB6")
        if not start_pos:print("wrong file!");sys.exit()
        fp.seek(start_pos+4+48+1)
        
        while 1:
            pd=pwTextData()
            try:
                #print(fp.tell())
                fstruct=int("%d"%struct.unpack('>I',fp.read(4)))
                #print(hex(fstruct))
                
                ## tagid 6 is the opera:encrypto info,i didn't resolve the data here
                ## so ,pass -_-!
                if fstruct==6:break 
                
                #while fstruct not in [2,1,3]:
                    #print("fstruct error,pos",fp.tell(),hex(fstruct))
                    #fstruct=int("%d"%struct.unpack('>I',fp.read(4)))
                while fstruct != 88:
                    ## the start of area flag is "\x58"
                    ##print("fstruct error,pos",fp.tell(),hex(fstruct))
                    fstruct=int("%d"%struct.unpack('>I',fp.read(4)))

            except:
                #print("except,pos:",fp.tell())
                break

            domain_info_count=1
            max_count=6
            spec=0
            #print("start")
            
            l=fstruct
            pd.key=getBlockData(fp,l)
            l=int("%d"%struct.unpack('>I',fp.read(4)))
            pd.timestamp=getBlockData(fp,l)
            l=int("%d"%struct.unpack('>I',fp.read(4)))
            pd.onurl=getBlockData(fp,l)

            before=fp.tell()
            while 1:
                l=int("%d"%struct.unpack('>I',fp.read(4)))
                
                if l==0 :continue
                if l>0 and l<8:
                    n=fp.read(16)
                    #print("ord(2)",l,"pass",fp.tell())
                    continue
                if l>=255 and l<65535:
                    #print("ord(l)",l,"break",fp.tell())
                    break
                if l>=65535 :n=fp.read(4);continue
                #if l<8 and l>3:max_count-=1;continue
                #elif l==1 or l==2 or l==3 or l>=32767:print("ord(l)",l,"break",fp.tell());break
                if l>=8 and l<255 :
                    pd.other.append(getBlockData(fp,l))

            #pd.fldsinfo_len=24
            #print("len pd.other len pd.other len pd.other:",len(pd.other))

            pd.flds_count=int("%d"%struct.unpack('>I',fp.read(4)))
            #print("pd.flds_count",pd.flds_count,fp.tell(),"read fileds........................",fp.tell())
            for i in xrange(pd.flds_count):
                tag_id=fp.read(1)
                #print("tag_id",ord(tag_id))
                d=[]
                for j in xrange(3):
                    ## each tag_id with 3 block, including an empty block
                    l=int("%d"%struct.unpack('>I',fp.read(4)))
                    if l<9 :
                        #print("ord(l)",l,fp.tell())
                        continue
                    d.append(getBlockData(fp,l))
                    #print("append data:",str(i)*3)
                pd.flds.append((tag_id,d[:]))
            ret.append(pd)
            #print("end")
            #print('*'*50)
            #print("stack here****",fp.tell())
    #print("len ret:",len(ret))
    
    if ret:
        return ret
    print("read file error!")
        
def DecryptPwTextData(tdata):
    ## tdata is an instants of pwTextData
    def Decrypt(d):
        if type(d) == type(""):
            return d
        else:
            return GetPrintable(DecryptBlock(d.key,d.data))
            
    try:
        
        tdata.key=Decrypt(tdata.key)

        tdata.timestamp=Decrypt(tdata.timestamp)
        tdata.onurl=Decrypt(tdata.onurl)
        #tdata.unknow_url=Decrypt(tdata.unknow_url)
        #tdata.domain=Decrypt(tdata.domain)
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
        print(pwdata.key)
        print(pwdata.timestamp)
        print(pwdata.onurl)
        #print(pwdata.unknow_url)
        #print(pwdata.domain)
        #print("other2_len",len(pwdata.other))
        if pwdata.other:
            print("otherUrlInfo:",pwdata.other2)
        
        #print(pwdata.fldsinfo_len)
        #print(pwdata.fldsinfo)
        print("data_fields_count",pwdata.flds_count)
        #print(pwdata.flds) # flds is encrypt data [(tag_id,[pwRawData,pwRawData,pwRawData]),]
        for i in pwdata.fields:
            print('\t',i) # fields is readable text data [(type,text),]
        print("*"*50)
