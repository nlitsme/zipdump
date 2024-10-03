#!/usr/bin/python3
"""
Analyze local or remote PKZIP file contents

 * scan entire file for PKxy headers
 * do quick scan by locating EOF header ( with the '-q' option )
 * can operate on .zip files from a http://URL

(C) 2016 Willem Hengeveld  <itsme@xs4all.nl>

"""

from __future__ import division, print_function, absolute_import, unicode_literals
import sys
import os
import binascii
import struct
import datetime
import zlib
import itertools
import errno

if sys.version_info[0] == 2:
    import scandir
    os.scandir = scandir.scandir

def md5_hex(x):
    import hashlib
    if type(x) == str:
        x = x.encode('utf-8')
    h = hashlib.new('md5')
    h.update(x)
    return h.hexdigest()

class DebugStream:
    def __init__(self, fh):
        self.fh = fh
    def seek(self, ofs, whence = 0):
        if ofs == 0xFFFFFFFF: raise Exception("BUG")
        r = self.fh.seek(ofs, whence)
        print("S: seek 0x%08x %d -> %s" % (ofs, whence, "None" if r is None else f"0x{r:08x}" ))
        return r
    def read(self, size=None):
        r = self.fh.read(size)
        print("S: read %s -> %s" % ("None" if size is None else f"0x{size:08x}",
                                    "None" if r is None else f"(0x{len(r):08x})" ))
        return r
    def tell(self):
        r = self.fh.tell()
        print("S: tell -> %s" % ("None" if r is None else f"0x{r:08x}" ))
        return r

def zip_decrypt(data, pw):
    """
    INPUT: data  - an array of bytes
           pw    - either a tuple of 3 dwords, or a byte array.
    OUTPUT: a decrypted array of bytes.

    The very weak 'zip' encryption

    This encryption can be cracked using tools like pkcrack.
    Pkcrack does a known plaintext attack, requiring 13 bytes of plaintext.
    """
    def make_crc_tab(poly):
        def calcentry(v, poly):
            for _ in range(8):
                v = (v>>1) ^ (poly if v&1 else 0)
            return v
        return [ calcentry(byte, poly) for byte in range(256) ]

    crctab = make_crc_tab(0xedb88320)

    def crc32(crc, byte):
        return crctab[(crc^byte)&0xff] ^ (crc>>8)

    def updatekeys(keys, byte):
        keys[0] = crc32(keys[0], byte)
        keys[1] = ((keys[1] + (keys[0]&0xFF)) * 134775813 + 1)&0xFFFFFFFF
        keys[2] = crc32(keys[2], keys[1]>>24)

    keys = [ 0x12345678, 0x23456789, 0x34567890 ]
    if type(pw)==list:
        keys = pw.copy()
    else:
        for c in pw:
            updatekeys(keys, c)

    for blk in data:
        u = bytearray()
        for b in bytearray(blk):
            xor = (keys[2] | 2)&0xFFFF
            xor = ((xor * (xor^1))>>8) & 0xFF
            b = b ^ xor
            u.append(b)
            updatekeys(keys, b)
        yield u


def skipbytes(blks, skip, args):
    """
    skip the first <skip> bytes of a stream of byte blocks.
    """
    skipped = b''
    for blk in blks:
        if skip >= len(blk):
            skip -= len(blk)
            skipped += blk
        elif skip:
            skipped += blk[:skip]
            if args.verbose:
                print("CRYPTHEADER: %s" % binascii.b2a_hex(skipped))
                sys.stdout.flush()
            yield blk[skip:]
            skip = 0
        else:
            yield blk


class EntryBase(object):
    """
    Base class for PK headers

    subclasses are supposed to add fields:
      - HeaderSize
      - MagicNumber
    Methods subclasses are required to implement:
     - __repr__()
     - reprPretty()
    Optional methods:
     - summary()
     - loaditems(fh)

    also, each object gets fields:
     - pkOffset  - file offset to 'PK' signature
     - endOffset - file offset to end of this item.
    """
    def loaditems(self, fh):
        """ loads any items refered to by the header """
        pass

    def summary(self):
        return ""

    @staticmethod
    def decode_name(name):
        """
        create an always somewhat readable name, without
        """
        nonprint = set('\u0009\u000b\u000c\u001c\u001d\u001e\u001f\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2008\u2009\u200a\u200b\u2026\u2028\u2029\u205f\u3000')
        try:
            utf8 = name.decode('utf-8', 'strict')
            if not nonprint & set(utf8) and utf8.isprintable():
                return utf8
        except:
            pass
        if len(name)>255:
            return "hex-%s" % md5_hex(name)
        return "hex-%s" % (binascii.b2a_hex(name).decode())

    @staticmethod
    def decodedatetime(ts):
        """
        Decode a pkzip / dos date + time into a datetime object.
        """
        def decode_date(dt):
            if dt==0:
                return datetime.datetime(1980,1,1)
            year, mon, day = (dt>>9), (dt>>5)&15, dt&31
            try:
                return datetime.datetime(year+1980, mon, day)
            except Exception as e:
                print("error decoding date %d-%d-%d" % (year+1980, mon, day))
                return datetime.datetime(1980,1,1)
        def decode_time(tm):
            hour, minute, bisecond = tm>>11, (tm>>5)&63, tm&31
            return datetime.timedelta(hours=hour, minutes=minute, seconds=bisecond*2)

        return decode_date(ts>>16) + decode_time(ts & 0xFFFF)


######################################################
#  Decoder classes
######################################################

class FileEntryBase(EntryBase):
    """
    FileEntryBase is the base class for CentralDirEntry's and
    LocalFileHeader's

    it provides fucntions for decoding flags and timestamps.
    """
    def __init__(self):
        self.atime = None
        self.mtime = None
        self.ctime = None

    def flagdesc(self, simple=False):
        # &8: localheader crc, size, usize are zero in localfileheader.
        # &32:  compressed patched data

        flags = { 1: "CRYPT", 8: "NOLFH", 32:"PATCH", 64:"AES" }

        testedflags = 0
        l = []

        # check single bit flags
        for flag, name in flags.items():
            if self.flags & flag:
                if simple:
                    return name
                testedflags |= flag
                l.append(name)

        # compression mode
        #
        # method == 6:
        # &2: 1=8k dict, 0=4k dict
        # &4: 1=3 shannon trees, 0=2 shannon trees

        # method == 8, 9:
        # &6
        #  0: Normal (-en) compression option was used.
        #  2: Maximum (-exx/-ex) compression option was used.
        #  4: Fast (-ef) compression option was used.
        #  6: Super Fast (-es) compression option was used.

        # method == 14 ( lzma)
        # &2: EOS marker present
        if self.flags & 6:
            testedflags |= 6
            l.append("CMODE%x" % ((self.flags&6)>>1))

        # remaining flags
        if self.flags & ~testedflags:
            l.append("UNK_%x" % (self.flags & ~testedflags))
        return "+".join(l)

    def get_atime(self):
        return self.atime or self.get_mtime()

    def get_ctime(self):
        return self.ctime or self.get_mtime()

    def get_mtime(self):
        return self.mtime or self.decodedatetime(self.timestamp).timestamp()

    def updateTimes(self, mtime, atime, ctime):
        if atime:
            self.atime = datetime.datetime.fromtimestamp(atime)
        if mtime:
            self.mtime = datetime.datetime.fromtimestamp(mtime)
        if ctime:
            self.ctime = datetime.datetime.fromtimestamp(ctime)

    def processExtra(self):
        o = 0
        while o+4 <= self.extraLength:
            tag, size = struct.unpack_from("<HH", self.extra, o)
            o += 4
            e = o + size
            if tag == 1: # zip64
                self.parseZip64(self.extra[o:e])
            elif tag == 10: # NTFS
                self.parseNtfs(self.extra[o:e])
            elif tag == 0x4453: # WinNT binary ACL
                pass
            elif tag == 0x5455: # extended timestamp
                self.parseTimestamp(self.extra[o:e])
            elif tag == 0x7855: # unix uid, gid
                self.parseUnixUID(self.extra[o:e])
            elif tag == 0x7875: # unix uid, gid
                self.parseUnixUIDNew(self.extra[o:e])
            elif tag == 0x5855: # info-zip unix
                self.parseInfoZip(self.extra[o:e])
            o = e

    def parseUnixUID(self, data):
        uid = gid = None
        o = 0
        if o == 0:
            return
        if o<4:
            print("WARNING: UnixUID: not enough data")
            return
        uid, gid = struct.unpack_from("<HH", data, 0)

    def parseUnixUIDNew(self, data):
        flag, = struct.unpack_from("<B", data, 0)
        uid = gid = None
        o = 1
        i = 0
        while o < len(data):
            l, = struct.unpack_from("<B", data, o)
            o += 1
            if l==1:
                fmt = "<B"
            elif l==2:
                fmt = "<H"
            elif l==4:
                fmt = "<L"
            elif l==8:
                fmt = "<!"
            else:
                print("WARNING: unknown uid size")
            value, = struct.unpack_from(fmt, data, o)
            o += l
            if i==0:
                uid = value
            elif i==1:
                gid = value
            else:
                print("WARNING: too many uid values")
            i += 1
        pass

    def parseTimestamp(self, data):
        atime = mtime = ctime = None
        flags, = struct.unpack_from("<B", data, 0)
        o = 1
        if flags&1:
            mtime, = struct.unpack_from("<L", data, o)
            o += 4
            if o==len(data): return
        if flags&2:
            atime, = struct.unpack_from("<L", data, o)
            o += 4
            if o==len(data): return
        if flags&4:
            ctime, = struct.unpack_from("<L", data, o)
            o += 4
            if o==len(data): return
        # TODO: use m, a, c time
        self.updateTimes(mtime, atime, ctime)

    def parseInfoZip(self, data):
        atime = mtime = ctime = None
        if len(data)<8:
            print("WARNING: infozip data < 8 bytes")
            return
        atime, mtime = struct.unpack_from("<LL", data, 0)
        # TODO: use atime, mtime
        self.updateTimes(mtime, atime, ctime)

    def parseNtfs(self, data):

        def cvWinNTTime(nttime):
            # convert 1601-01-01  .1usec epoch to  1970-01-01 1.0sec epoch
            nttime /= 10000000
            return nttime - 11644473600

        atime = mtime = ctime = None
        o = 0
        while o < len(data):
            tag, size = struct.unpack_from("<HH", data, o)
            o += 4
            if tag == 1:
                if size != 0x18:
                    print("WARNING: expected NTFS tag#1 of size 24")
                mtime, atime, ctime = struct.unpack_from("<QQQ", data, o)
                # TODO: set m, a, c time
                self.updateTimes(cvWinNTTime(mtime), cvWinNTTime(atime), cvWinNTTime(ctime))
            o += size

    def parseZip64(self, data):
        o = 0
        # zip64
        # note: LFH must contain both, while the direntry may contain one or both.
        if self.originalSize == 0xFFFFFFFF:
            if o+8 > len(data):
                print("WARNING: not enough data for origsize64")
            self.originalSize64, = struct.unpack_from("<Q", data, o)
            o += 8
        if self.compressedSize == 0xFFFFFFFF:
            if o+8 > len(data):
                print("WARNING: not enough data for compsize64")
            self.compressedSize64, = struct.unpack_from("<Q", data, o)
            o += 8
        if hasattr(self, 'dataOfs') and self.dataOfs == 0xFFFFFFFF:
            # only for centraldir.
            if o+8 > len(data):
                print("WARNING: not enough data for dataofs64")
            self.dataOfs64, = struct.unpack_from("<Q", data, o)
            o += 8

        # disk start number

    def getOriginalSize(self):
        # if flags&8 -> value is in data-descriptor(0708) and centraldir
        if self.originalSize64 is not None:
            return self.originalSize64
        if isinstance(self, CentralDirEntry) or self.flags&8==0:
            return self.originalSize

    def getCompressedSize(self):
        # if flags&8 -> value is in data-descriptor(0708) and centraldir
        if self.compressedSize64 is not None:
            return self.compressedSize64
        if isinstance(self, CentralDirEntry) or self.flags&8==0:
            return self.compressedSize

    def getDataOfs(self):
        if self.dataOfs64 is not None:
            return self.dataOfs64
        return self.dataOfs

"""
note about version-made-by:
    0 = FAT
    1 = amiga, 2=openvms, 3=unix, 4=vm/cms
    5 = atarist, 6=hpfs, 7=mac, 8=z-sys, 9=cpm
    10= ntfs, 11=ntfs
    14= vfat, 16=beos
"""

class CentralDirEntry(FileEntryBase):
    HeaderSize = 42
    MagicNumber = b'\x01\x02'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.compressedSize64 = None
        self.originalSize64 = None
        self.dataOfs64 = None
        # createVersion has the OS in the high byte, 0 = dos/win, 3 = unix

        (
            self.createVersion,
            self.neededVersion,
            self.flags,
            self.method,
            self.timestamp,
            self.crc32,
            self.compressedSize,
            self.originalSize,
            self.nameLength,
            self.extraLength,
            self.commentLength,
            self.diskNrStart,
            self.zipAttrs,
            self.osAttrs,
            self.dataOfs 
        ) = struct.unpack_from("<4H4L5HLL", data, ofs)

        ofs += self.HeaderSize

        self.nameOffset = baseofs + ofs
        ofs += self.nameLength

        self.extraOffset = baseofs + ofs
        ofs += self.extraLength

        self.commentOffset = baseofs + ofs
        ofs += self.commentLength

        self.endOffset = baseofs + ofs

        self.name = None
        self.extra = None
        self.comment = None

    def loaditems(self, fh):
        fh.seek(self.nameOffset)
        self.name = self.decode_name(fh.read(self.nameLength))
        fh.seek(self.extraOffset)
        self.extra = fh.read(self.extraLength)
        fh.seek(self.commentOffset)
        self.comment = fh.read(self.commentLength).decode("utf-8", "ignore")
        self.processExtra()

    def summary(self):
        return "%10d (%5.1f%%)  %s  %08x [%5s] %s" % (
                self.getOriginalSize(),
                100.0*self.getCompressedSize()/self.getOriginalSize() if self.getOriginalSize() else 0,
                self.decodedatetime(self.timestamp),
                self.crc32,
                self.flagdesc(simple=True),
                self.name
                )

    def __repr__(self):
        #             cver ver  fl   mth  ts  crc   csiz osiz nl   xl   cl   d0   zatr osat dofs
        r = "PK.0102: %04x %04x %04x %04x %08x %08x %08x %08x %04x %04x %04x %04x %04x %08x %08x |  %08x %08x %08x %08x" % (
            self.createVersion, self.neededVersion, self.flags, self.method, self.timestamp,
            self.crc32, self.compressedSize, self.originalSize, self.nameLength, self.extraLength,
            self.commentLength, self.diskNrStart, self.zipAttrs, self.osAttrs, self.dataOfs,
            self.nameOffset, self.extraOffset, self.commentOffset, self.endOffset)
        if self.name:
            r += " - " + self.name
        return r

    def reprPretty(self):
        r = "PK.0102: %s\n" % self.__class__.__name__
        r += "\tversion made by:        %04x\n" % self.createVersion
        r += "\tversion needed to extr: %04x\n" % self.neededVersion
        r += "\tflags:                  %04x - [%s]\n" % (self.flags, self.flagdesc())
        r += "\tcompression:            %04x\n" % self.method
        r += "\ttime & date:            %08x\n" % self.timestamp
        r += "\tcrc-32:                 %08x\n" % self.crc32
        r += "\tcompressed size:        %08x\n" % self.compressedSize
        r += "\toriginal size:          %08x\n" % self.originalSize
        r += "\tname length:            %04x\n" % self.nameLength
        r += "\textra field length:     %04x\n" % self.extraLength
        r += "\tcomment length:         %04x\n" % self.commentLength
        r += "\tdisk number start:      %04x\n" % self.diskNrStart
        r += "\tinternal attributes:    %04x\n" % self.zipAttrs
        r += "\texternal attributes:    %08x\n" % self.osAttrs
        r += "\tlocal header offset:    %08x\n" % self.dataOfs
        r += "\tfile name offset        %08x" % self.nameOffset
        r += " - " + self.name + "\n" if self.name else "\n"
        r += "\textra field offset      %08x\n" % self.extraOffset
        r += "\t\t%s\n" % binascii.b2a_hex(self.extra)
        r += "\tcomment offset          %08x" % self.commentOffset
        r += "\t" + self.comment + "\n" if self.comment else "\n"
        r += "\tend offset              %08x\n" % self.endOffset
        return r

    def havetimes(self):
        return True

    def havemode(self):
        return True

    def get_mode(self):
        return self.osAttrs >> 16

    def isdir(self):
        # for unix: upper 16 bits contain file perms.
        # lower 16 bits: 0 for regular, 16 for directory
        return (self.osAttrs & 65535) == 16

    def islink(self):
        # for unix: upper 16 bits contain file perms.
        # lower 16 bits: 0 for regular, 16 for directory
        return (self.osAttrs >> 16) & 0o170000 == 0o120000 


"""
Note about flags:
       0 - encrypted
       method 6 (imploding)
           1  -> 0=4k dict, 1=8K dict
           2  -> 0=2 trees, 1=3 trees
       method 8, 9 (Deflating)
         00 - normal
         01 - max
         10 - fast
         11 - super
       
       3 - crc32, compsize, uncompsize are empty in LFH
           see datadesc after the data.
       5 - packed data

note about method:
    0 - stored
    1 - shrunk
    2-5 - reduced-1..4
    6 - imploded
    7 - tokenized
    8 - deflated
    9 - enhanced deflate
   10 - pkware implode
"""
class LocalFileHeader(FileEntryBase):
    HeaderSize = 26
    MagicNumber = b'\x03\x04'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.compressedSize64 = None
        self.originalSize64 = None

        (
            self.neededVersion,
            self.flags,           # bit3: have datadesc
            self.method,
            self.timestamp,
            self.crc32,
            self.compressedSize,
            self.originalSize,
            self.nameLength,
            self.extraLength 
        ) = struct.unpack_from("<3H4LHH", data, ofs)
        ofs += self.HeaderSize

        self.nameOffset = baseofs + ofs
        ofs += self.nameLength

        self.extraOffset = baseofs + ofs
        ofs += self.extraLength

        self.dataOffset = baseofs + ofs
        if self.compressedSize == 0xFFFFFFFF:
            # Note: will fill these in later from the 'XTRA' field.
            self.endOffset = None
        elif self.flags&8==0:
            ofs += self.compressedSize      #### TODO unknown for zip64 until extra info is read.
            self.endOffset = baseofs + ofs
        else:
            self.endOffset = None

        self.name = None
        self.extra = None
        self.data = None

    def loaditems(self, fh):
        fh.seek(self.nameOffset)
        self.name = self.decode_name(fh.read(self.nameLength))
        fh.seek(self.extraOffset)
        self.extra = fh.read(self.extraLength)
        # not loading data

        self.processExtra()

        if self.endOffset is None and self.flags&8==0:
            self.endOffset = self.dataOffset + self.getCompressedSize()

    def __repr__(self):
        def ornone(x):
            if x is None: return "--------"
            return "%08x" % x

        #             ver  fl   mth  ts  crc   csiz osiz nlen xlen
        r = "PK.0304: %04x %04x %04x %08x %08x %08x %08x %04x %04x |  %08x %08x %08x %s" % (
            self.neededVersion, self.flags, self.method, self.timestamp, self.crc32,
            self.compressedSize, self.originalSize, self.nameLength, self.extraLength,
            self.nameOffset, self.extraOffset, self.dataOffset, ornone(self.endOffset))
        if self.name:
            r += " - " + self.name
        return r

    def reprPretty(self):
        r = "PK.0304: %s\n" % self.__class__.__name__
        r += "\tversion needed to extr: %04x\n" % self.neededVersion
        r += "\tflags:                  %04x - [%s]\n" % (self.flags, self.flagdesc())
        r += "\tcompression:            %04x\n" % self.method
        r += "\ttime & date:            %08x\n" % self.timestamp
        r += "\tcrc-32:                 %08x\n" % self.crc32
        r += "\tcompressed size:        %08x%s\n" % (self.compressedSize, " (%010x)" % self.compressedSize64 if self.compressedSize64 is not None else "")
        r += "\toriginal size:          %08x%s\n" % (self.originalSize,   " (%010x)" % self.originalSize64 if self.originalSize64 is not None else "")
        r += "\tname length:            %04x\n" % self.nameLength
        r += "\textra field length:     %04x\n" % self.extraLength
        r += "\tname offset:            %08x" % self.nameOffset
        r += " - " + self.name + "\n" if self.name else "\n"
        r += "\textra offset:           %08x\n" % self.extraOffset
        r += "\t\t%s\n" % binascii.b2a_hex(self.extra)
        r += "\tdata offset:            %08x\n" % self.dataOffset
        r += "\tend offset:             %08x\n" % self.endOffset
        return r

    def havetimes(self):
        return (self.flags & 8) == 0

    def havemode(self):
        return False

    def get_mode(self):
        return None

    def isdir(self):
        # determine if this is an entry for a directory heuristically
        return self.crc32 == 0 and self.name.endswith('/')

    def islink(self):
        # actually, from the local file ent there is no way to tell if this is a link or a file.
        return False


class EndOfCentralDir(EntryBase):
    HeaderSize = 18
    MagicNumber = b'\x05\x06'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        (
        self.thisDiskId,
        self.dirDiskIdStart,
        self.thisDiskNrEntries,
        self.totalNrEntries,
        self.dirSize,
        self.dirOffset,
        self.commentLength,
        )= struct.unpack_from("<4HLLH", data, ofs)
        ofs += self.HeaderSize

        self.commentOffset = baseofs + ofs
        ofs += self.commentLength

        self.endOffset = baseofs + ofs

        self.comment = None

    def size(self):
        return self.HeaderSize + self.commentLength + 4

    def loaditems(self, fh):
        if not self.commentLength:
            return
        fh.seek(self.commentOffset)
        self.comment = fh.read(self.commentLength)
        if self.comment.startswith(b'signed by SignApk'):
            self.comment = repr(self.comment[:17]) + str(binascii.b2a_hex(self.comment[18:]), 'ascii')
        else:
            self.comment = self.comment.decode('utf-8', 'ignore')

    def summary(self):
        if self.thisDiskNrEntries==self.totalNrEntries:
            r = "EOD: %d entries" % (self.totalNrEntries)
        else:
            r = "Spanned archive %d .. %d  ( %d of %d entries )" % (self.dirDiskIdStart, self.thisDiskId, self.thisDiskNrEntries, self.totalNrEntries)
        r += ", %d byte directory" % self.dirSize
        return r

    def __repr__(self):
        r = "PK.0506: %04x %04x %04x %04x %08x %08x %04x |  %08x %08x" % (
            self.thisDiskId, self.dirDiskIdStart, self.thisDiskNrEntries, self.totalNrEntries, self.dirSize, self.dirOffset, self.commentLength,
            self.commentOffset, self.endOffset)
        return r

    def reprPretty(self):
        r = "PK.0506: %s\n" % self.__class__.__name__
        r += "\tdisk number:             %04x\n" % self.thisDiskId
        r += "\tcentral dir disk number: %04x\n" % self.dirDiskIdStart
        r += "\tcentral dir entries:     %04x\n" % self.thisDiskNrEntries
        r += "\ttotal entries:           %04x\n" % self.totalNrEntries
        r += "\tcentral dir size:        %08x\n" % self.dirSize
        r += "\tcentral dir offset:      %08x\n" % self.dirOffset
        r += "\tcomment length:          %04x\n" % self.commentLength
        r += "\tcomment offset:          %08x" % self.commentOffset
        r += "\t" + self.comment + "\n" if self.comment else "\n"
        r += "\tend offset:              %08x\n" % self.endOffset
        return r


class DataDescriptor(EntryBase):
    HeaderSize = 12
    MagicNumber = b'\x07\x08'

    # NOTE: conflict with disk spanning marker

    # TODO: combine this and the LFH to get the sizes.

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        (
            self.crc,
            self.compSize,
            self.uncompSize,
        ) = struct.unpack_from("<3L", data, ofs)
        ofs += self.HeaderSize

        self.endOffset = baseofs + ofs

    def __repr__(self):
        return "PK.0708: %08x %08x %08x |  %08x" % (
            self.crc, self.compSize, self.uncompSize,
            self.endOffset)

    def reprPretty(self):
        r = "PK.0708: %s\n" % self.__class__.__name__
        r += "\tcrc-32:          %08x\n" % self.crc
        r += "\tcompressed size: %08x\n" % self.compSize
        r += "\toriginal size:   %08x\n" % self.uncompSize
        r += "\tend offset:      %08x\n" % self.endOffset
        return r


class Zip64EndOfDir(EntryBase):
    HeaderSize = 52
    MagicNumber = b'\x06\x06'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        (
            self.hdrsize,
            self.versionMadeBy,
            self.versionNeeded,
            self.thisDiskId,
            self.dirDiskIdStart,
            self.thisDiskNrEntries,
            self.totalNrEntries,
            self.dirSize,
            self.dirOffset,
        ) = struct.unpack_from("<QHHLLQQQQ", data, ofs)

        # TODO: if versionMadeBy >= 62
        #  -> v2 header
        #  2 bytes          Compression Method        Method used to compress the Central Directory
        #  8 bytes          Compressed Size           Size of the compressed data
        #  8 bytes          Original   Size           Original uncompressed size
        #  2 bytes          AlgId                     Encryption algorithm ID
        #  2 bytes          BitLen                    Encryption key length
        #  2 bytes          Flags                     Encryption flags
        #  2 bytes          HashID                    Hash algorithm identifier
        #  2 bytes          Hash Length               Length of hash data
        #  (variable)       Hash Data                 Hash data

        ofs += self.HeaderSize
        self.extensibleOffset = baseofs + ofs
        self.extensibleData = data[ofs:ofs + self.hdrsize-(self.HeaderSize-8)]

        ofs += self.hdrsize-(self.HeaderSize-8)

        self.endOffset = baseofs + ofs

    def summary(self):
        if self.thisDiskNrEntries==self.totalNrEntries:
            r = "EOD64: %d entries" % (self.totalNrEntries)
        else:
            r = "Spanned archive %d .. %d  ( %d of %d entries )" % (self.dirDiskIdStart, self.thisDiskId, self.thisDiskNrEntries, self.totalNrEntries)
        r += ", %d byte directory" % self.dirSize
        return r

    def __repr__(self):
        return "PK.0606: %010x %04x %04x %4d/%4d %010x %010x %010x %010x | %010x %010x" % (
            self.hdrsize,
            self.versionMadeBy,
            self.versionNeeded,
            self.thisDiskId,
            self.dirDiskIdStart,
            self.thisDiskNrEntries,
            self.totalNrEntries,
            self.dirSize,
            self.dirOffset,
            self.extensibleOffset,
            self.endOffset,
        )

    def reprPretty(self):
        r = "PK.0606: %s\n" % self.__class__.__name__
        r += "\tHeader size:                %08x\n" %  self.hdrsize
        r += "\tVersion Made:               %04x\n" %  self.versionMadeBy
        r += "\tVersion Needed:             %04x\n" %  self.versionNeeded
        r += "\tdisk number:                %04x\n" %  self.thisDiskId
        r += "\tcentral dir disk number:    %04x\n" %  self.dirDiskIdStart
        r += "\tthis central dir nr entries:%08x\n" %  self.thisDiskNrEntries
        r += "\tcentral dir total entries:  %08x\n" %  self.totalNrEntries
        r += "\tcentral dir size:           %08x\n" %  self.dirSize
        r += "\tcentral dir offset:         %010x\n" % self.dirOffset
        return r


class Zip64EndOfDirLocator(EntryBase):
    HeaderSize = 16
    MagicNumber = b'\x06\x07'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        (
            self.eodDiskId,
            self.eodOffset,
            self.nrOfDisks,
        ) = struct.unpack_from("<LQL", data, ofs)
        ofs += self.HeaderSize
        self.endOffset = baseofs + ofs

    def summary(self):
        return "LOC64 (%d of %d) -> 0x%010x" % (self.eodDiskId, self.nrOfDisks, self.eodOffset)

    def __repr__(self):
        return "PK.0607: %08x %010x %08x |  %08x" % (
            self.eodDiskId, self.eodOffset, self.nrOfDisks,
            self.endOffset)

    def reprPretty(self):
        r = "PK.0607: %s\n" % self.__class__.__name__
        r += "\tEOD64 disk number: %04x\n" % self.eodDiskId
        r += "\tEOD64 offset:      %010x\n" % self.eodOffset
        r += "\tEOD64 total disks: %04x\n" % self.nrOfDisks
        return r


class ArchiveExtraDataEntry(EntryBase):
    HeaderSize = 4
    MagicNumber = b'\x06\x08'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        self.size, = struct.unpack_from("<L", data, ofs)
        ofs += self.HeaderSize

        self.field = data[ofs:ofs+self.size]
        ofs += self.size

        self.endOffset = baseofs + ofs

    def __repr__(self):
        return "PK.0806 %02x  | %08x" % (self.size, self.endOffset)

    def reprPretty(self):
        r = "PK.0806: %s\n" % self.__class__.__name__
        r += "\tsize  : %04x\n" % self.size
        r += "\tfield : %s\n" % binascii.b2a_hex(self.field)
        return r


class SingleSpannedArchiveMarker(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x07\x08'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        self.endOffset = self.pkOffset + 4

    def __repr__(self):
        return "PK.0708"

    def reprPretty(self):
        r = "PK.0708: %s\n" % self.__class__.__name__
        return r


class SpannedArchiveMarker(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x30\x30'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        self.endOffset = self.pkOffset + 4

    def __repr__(self):
        return "PK.3030"

    def reprPretty(self):
        r = "PK.3030: %s\n" % self.__class__.__name__
        return r


class ArchiveSignature(EntryBase):
    HeaderSize = 2
    MagicNumber = b'\x05\x05'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4
        self.size, = struct.unpack_from("<H", data, ofs)
        ofs += self.HeaderSize
        self.signature = data[ofs:ofs+self.size]
        ofs += self.size
        self.endOffset = baseofs + ofs

    def __repr__(self):
        return "PK.0505 %02x  | %08x" % (self.size, self.endOffset)

    def reprPretty(self):
        r = "PK.0505: %s\n" % self.__class__.__name__
        r += "\tsize  : %04x\n" % self.size
        r += "\tsig   : %s\n" % binascii.b2a_hex(self.signature)
        return r


def getDecoderClass(typ):
    """ Return Decoder class for the PK type. """
    for cls in (CentralDirEntry, LocalFileHeader, EndOfCentralDir, DataDescriptor, Zip64EndOfDir, Zip64EndOfDirLocator, ArchiveExtraDataEntry, ArchiveSignature, ):
        if cls.MagicNumber == typ:
            return cls


def getMarkerClass(typ):
    """ Return Marker class for the PK type. """
    for cls in (SpannedArchiveMarker, SingleSpannedArchiveMarker, ):
        if cls.MagicNumber == typ:
            return cls


def findPKHeaders(args, fh):
    """ Scan the entire file for PK headers. """

    def processchunk(o, chunk):
        n = -1
        while True:
            n = chunk.find(b'PK', n+1)
            if n == -1 or n+4 > len(chunk):
                break

            # first try markers, which are followed immediately by another PK tag.
            if n+8 <= len(chunk) and chunk[n+4:n+6] == b'PK' and getDecoderClass(chunk[n+6:n+8]):
                cls = getMarkerClass(chunk[n+2:n+4])
                if cls:
                    yield cls(o, chunk, n+4)
                    continue

            # then try the regular PK tags.
            cls = getDecoderClass(chunk[n+2:n+4])
            if cls:
                hdrEnd = n+4+cls.HeaderSize
                if hdrEnd > len(chunk):
                    continue

                # todo: skip entries entirely within repeated chunk
                # if n<64 and hdrEnd>64:
                #    continue

                yield cls(o, chunk, n+4)

    prev = b''
    o = 0
    if args.offset:
        fh.seek(args.offset, os.SEEK_SET if args.offset >= 0 else os.SEEK_END)
        o = args.offset
    while args.length is None or o < args.length:
        want = args.chunksize
        if args.length is not None and want > args.length - o:
            want = args.length - o
        fh.seek(o)
        chunk = fh.read(want)
        if len(chunk) == 0:
            break
        for ch in processchunk(o-len(prev), prev+chunk):
            yield ch

        # 64 so all header types would fit, exclusive their variable size parts
        prev = chunk[-64:]
        o += len(chunk)


def quickScanZip(args, fh):
    """
    Do a quick scan of the .zip file, starting by locating the EOD marker.

    args.offset can be updated by this funtion.
    """
    # 100 bytes is the smallest .zip possible

    fh.seek(0, os.SEEK_END)
    filesize = fh.tell()
    if filesize==0:
        print("Empty file")
        return
    if filesize<100:
        print("Zip too small: %d bytes, minimum zip is 100 bytes" % filesize)
        return

    # always keep 'eoddata' and 'ofs'  consistent.
    #   ofs is the absolute file position where eoddata was read from.

    # read last 120 bytes of the file.
    ofs = max(filesize-120, 0)
    fh.seek(ofs, os.SEEK_SET)
    eoddata = fh.read()

    iEND = eoddata.rfind(b'PK'+EndOfCentralDir.MagicNumber)
    if iEND==-1:
        # try with larger chunk
        # 0x10000 + 0x200 = max eod + filecomment + zip64 locator size
        ofs = max(filesize-0x10200, 0)
        fh.seek(ofs, os.SEEK_SET)
        eoddata = fh.read()

        iEND = eoddata.rfind(b'PK'+EndOfCentralDir.MagicNumber)
        if iEND==-1:
            print("expected PK0506 - probably not a PKZIP file")
            return

    eod = EndOfCentralDir(ofs, eoddata, iEND+4)
    yield eod

    if eod.endOffset < filesize:
        print("Extra data after EOD marker: 0x%x bytes" % (filesize - eod.endOffset))
    elif eod.endOffset > filesize:
        print("Strange: EOD marker after EOF: 0x%x" % (eod.endOffset - filesize))

    # we found 'eod32.pkOffset'
    #   when eod32.cdir_ofs != -1
    #     --> eod32.pkOffset - oed32.cdir_size  == dirent[0].pkOffset
    #     --> eod32.cdir_ofs - dirent[0].pkOffset   is the nr of extra bytes at the start of the file.
    #
    #   otherwise:
    #    loc64.pkOffset = eod32.pkOffset - 20
    #    loc64.eod_ofs  is only useful when we assume 0 extra bytes before the file.
    #    eod64.pkOffset - eod64.cdir_size == eod64.cdir_ofs
        #print("o=%x, i=%x : %s" % (ofs, iEND, binascii.b2a_hex(eoddata)))

    if eoddata[iEND-20:iEND-16] == b'PK'+Zip64EndOfDirLocator.MagicNumber:
        loc64 = Zip64EndOfDirLocator(ofs, eoddata, iEND-20+4)
        yield loc64

        # now try to find the eod64 record.
        if loc64.eodOffset < ofs:
            # need more data
            ofs = loc64.eodOffset
            endofs = 0
            fh.seek(ofs, os.SEEK_SET)
            eoddata = fh.read()
        else:
            endofs = loc64.eodOffset - ofs

        if eoddata[endofs:endofs+4] != b'PK'+Zip64EndOfDir.MagicNumber:
            print("WARNING: did not find zip64 eod - %s" % binascii.b2a_hex(eoddata[endofs:endofs+4]))
            return

        eod = Zip64EndOfDir(ofs, eoddata, endofs+4)
        yield eod
    elif eod.dirOffset == 0xFFFFFFFF:
        print("WARNING: did not find zip64 locator - %s" % binascii.b2a_hex(eoddata[iEND-20:iEND-16]))
        return

    if eod.dirOffset != 0xFFFFFFFF:
        if eod.dirOffset + eod.dirSize < eod.pkOffset:
            #print("dir=%x, size=%x, pk=%x, end=%x" % (eod.dirOffset, eod.dirSize, eod.pkOffset, eod.endOffset))
            print("Extra data before the start of the file: 0x%x bytes" % (eod.pkOffset - (eod.dirOffset + eod.dirSize)))
            args.offset = eod.pkOffset - (eod.dirOffset + eod.dirSize)
        elif eod.dirOffset + eod.dirSize > eod.pkOffset:
            print("Strange: directory overlaps with the EOD marker by %d bytes" % ((eod.dirOffset + eod.dirSize) - eod.pkOffset))

    dirofs = eod.pkOffset - eod.dirSize
    for _ in range(eod.thisDiskNrEntries):
        fh.seek(dirofs)
        dirdata = fh.read(46)
        if dirdata[:4] != b'PK' + CentralDirEntry.MagicNumber:
            print("expected PK0102")
            return
        dirent = CentralDirEntry(dirofs, dirdata, 4)

        yield dirent
        dirofs = dirent.endOffset


def findentry(entries):
    for ent in entries:
        pass

def getLFH(fh, pkbaseofs, ent):
    if isinstance(ent, CentralDirEntry):
        # find LocalFileHeader
        fh.seek(pkbaseofs + ent.getDataOfs())
        data = fh.read(4+LocalFileHeader.HeaderSize)
        dirent = ent
        ent = LocalFileHeader(pkbaseofs + ent.getDataOfs(), data, 4)

        ent.loaditems(fh)

    return ent


def zipraw(fh, pkbaseofs, ent):
    """
    yields the raw data blocks for a file entry.
    """
    lfh = getLFH(fh, pkbaseofs, ent)
    compsize = lfh.getCompressedSize() or ent.getCompressedSize()

    fh.seek(lfh.dataOffset)
    nread = 0
    while nread < compsize:
        want = min(compsize-nread, 0x10000)
        block = fh.read(want)
        if len(block)==0:
            break
        yield block
        nread += len(block)


def blockdump(baseofs, blks, limit):
    """
    Output a hexdump of the `blks` generator.
    """
    o = baseofs
    if limit:
        e = baseofs + limit
    else:
        e = None
    for blk in blks:
        want = o+len(blk)
        if e and want>e:
            want = e
        print("%08x: %s" % (o, binascii.b2a_hex(blk[:want])))
        o += len(blk)

        if e and o >= e:
            break


def zipcat(blks, ent):
    """
    Generator which decompresses data from the `blks` generator.
    8 = zip
    0 = stored
    """
    if ent.method==8:
        C = zlib.decompressobj(-15)
        for block in blks:
            yield C.decompress(block)
        yield C.flush()
    elif ent.method==0:
        yield from blks
    else:
        print("unknown compression method")


def namegenerator(name):
    yield name
    paths = name.rsplit('/', 1)
    parts = paths[-1].rsplit('.', 1)

    if len(paths)>1:
        part0 = "%s/%s" % ("".join(paths[:-1]), parts[0])
    else:
        part0 = parts[0]

    if len(parts)>1:
        part1 = ".%s" % (parts[1])
    else:
        part1 = ""

    for i in itertools.count(1):
        yield "%s-%d%s" % (part0, i, part1)

def is_subdir(basedir, path):
    """
    Make sure path is within basedir
    """

    # note: realpath expands any symlinks.
    absbase = os.path.realpath(basedir)
    abspath = os.path.realpath(path)
    return absbase == os.path.commonpath([absbase, abspath])

def ensure_dirs(dirpath):
    cur = '/' if os.path.isabs(dirpath) else None
    for p in dirpath.split('/'):
        if cur is None:
            todo = p
        else:
            todo = os.path.join(cur, p)
        for _ in range(2):
            try:
                os.stat(todo)
            except OSError as e:
                # optionally update p
                if e.errno == errno.ENAMETOOLONG :
                    p = md5_hex(p.encode('utf-8'))
                elif e.errno == errno.ENOENT:
                    os.mkdir(todo)
                else:
                    raise e
            break

        if cur is None:
            cur = p
        else:
            cur = os.path.join(cur, p)

    return cur

def savefile(args, ent, name, data):
    """
    Saves all data from the `data` generator to the specified file.
    """
    fullpath = os.path.join(args.outputdir, name)

    if not is_subdir(args.outputdir, fullpath):
        if args.debug or not args.allowdotdot:
            raise Exception("path tries to escape outputdir")
        print("WARNING: path tries to escape outputdir: ", fullpath)

    # todo: handle too-long basedir path components.
    ensure_dirs(os.path.dirname(fullpath))
    for namei in namegenerator(name):
        if len(namei)>255:
            namei = md5_hex(namei)
        path = os.path.join(args.outputdir, namei)
        if not os.path.exists(path):
            break
    try:
        if ent.islink():
            os.symlink(b"".join(data).decode('utf-8'), path)
        else:
            with open(path, "wb") as fh:
                fh.writelines(data)
    except OSError as e:
        if args.debug:
            raise
        print("WARNING: %s" % e)
        return

    if args.preserve and ent.havetimes():
        os.utime(path, (ent.get_atime(), ent.get_mtime()))
    if args.preserve and ent.havemode():
        os.chmod(path, ent.get_mode())


def getbytes(fh, ofs, size):
    fh.seek(ofs)
    return fh.read(size)


def processfile(args, fh):
    """ Process one opened file / url. """
    if args.streamdebug:
        fh = DebugStream(fh)
    if args.analyze:
        scanner = findPKHeaders(args, fh)
    else:
        scanner = quickScanZip(args, fh)

    def checkarg(arglist, ent):
        """
        Returns true when 'ent' is in arglist, or when arglist contains a wildcard.
        """
        if not arglist:
            return False
        return '*' in arglist or  ent.name in arglist

    if args.verbose and not (args.cat or args.raw or args.save):
        print("   0304            need flgs  mth    stamp  --crc-- compsize fullsize nlen xlen      namofs     xofs   datofs   endofs")
        print("   0102            crea need flgs  mth    stamp  --crc-- compsize fullsize nlen xlen clen dsk0 attr osattr     datptr      namofs     xofs   cmtofs   endofs")
    for ent in scanner:
        if args.cat or args.raw or args.save or args.extract:

            #
            # in 'quick' mode, use CentralDirEntry,
            # in 'full scan' mode, use LocalFileHeader.
            #  --> some problems with this: sometimes the lfh has only dummy values.
            #  and the lfh does not know if it is a directory.
            #
            if not args.analyze and isinstance(ent, CentralDirEntry)  or \
                        args.analyze and isinstance(ent, LocalFileHeader):
                ent.loaditems(fh)
                do_cat = checkarg(args.cat, ent)
                do_raw = checkarg(args.raw, ent)
                do_save= checkarg(args.save, ent)

                if (do_cat or do_raw) and not args.quiet:
                    # TODO: add option to omit this line, so i can pipe directly to another tool.
                    print("\n===> " + ent.name + " <===\n")

                sys.stdout.flush()

                blks = zipraw(fh, args.offset or 0, ent)   # note that this is a generator.

                if args.password and ent.flags&1:
                    blks = zip_decrypt(blks, args.password)
                    if do_cat or do_save:
                        blks = skipbytes(blks, 12, args)

                if do_cat:
                    sys.stdout.buffer.writelines(zipcat(blks, ent))
                if do_raw:
                    sys.stdout.buffer.writelines(blks)
                if do_save:
                    savefile(args, ent, ent.name, zipcat(blks, ent))

                if args.extract and not ent.isdir():
                    savename = ent.name
                    if args.strip:
                        f = ent.name.split('/')
                        savename = '/'.join(f[args.strip:])
                    savefile(args, ent, savename, zipcat(blks, ent))
        else:
            ent.loaditems(fh)
            if args.pretty:
                print("%08x: %s" % (ent.pkOffset, ent.reprPretty()))
            elif args.verbose or args.analyze:
                print("%08x: %s" % (ent.pkOffset, ent))
            else:
                print(ent.summary())
                if hasattr(ent, "comment") and ent.comment and not args.dumpraw:
                    print(ent.comment)

            if args.verbose>1 and hasattr(ent, "extraLength") and ent.extraLength:
                print("%08x: XTRA: %s" % (ent.extraOffset, binascii.b2a_hex(getbytes(fh, ent.extraOffset, ent.extraLength))))
            if args.verbose>1 and hasattr(ent, "comment") and ent.comment:
                print("%08x: CMT: %s" % (ent.commentOffset, binascii.b2a_hex(getbytes(fh, ent.commentOffset, ent.commentLength))))
            if args.dumpraw and isinstance(ent, LocalFileHeader):
                blks = zipraw(fh, args.offset or 0, ent)
                if args.password and ent.flags&1:
                    blks = list(blks)    # change generator into a list
                    blockdump(ent.dataOffset, blks, args.limit)
                    blks = zip_decrypt(blks, args.password)

                blockdump(ent.dataOffset, blks, args.limit)


def DirEnumerator(args, path):
    """
    Enumerate all files / links in a directory,
    optionally recursing into subdirectories,
    or ignoring links.
    """
    for d in os.scandir(path):
        try:
            if d.name == '.' or d.name == '..':
                pass
            elif d.is_symlink() and args.skiplinks:
                pass
            elif d.is_file():
                yield d.path
            elif d.is_dir() and args.recurse:
                for f in DirEnumerator(args, d.path):
                    yield f
        except Exception as e:
            print("EXCEPTION %s accessing %s/%s" % (e, path, d.name))


def EnumeratePaths(args, paths):
    """
    Enumerate all urls, paths, files from the commandline
    optionally recursing into subdirectories.
    """
    for fn in paths:
        try:
            # 3 - for ftp://, 4 for http://, 5 for https://
            if fn.find("://") in (3,4,5):
                yield fn
            if os.path.islink(fn) and args.skiplinks:
                pass
            elif os.path.isdir(fn) and args.recurse:
                for f in DirEnumerator(args, fn):
                    yield f
            elif os.path.isfile(fn):
                yield fn
        except Exception as e:
            print("EXCEPTION %s accessing %s" % (e, fn))


def main():
    import argparse

    class MultipleOptions(argparse.Action):
        """
        Helper class for supporting multiple options of the same name with argparse.

            --xyz ARG1  --xyz ARG2

        will result in an array value args.xyz = [ 'AGRG1', 'ARG2' ]
        """
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(MultipleOptions, self).__init__(option_strings, dest, **kwargs)
        def __call__(self, parser, namespace, values, option_string=None):
            arr = getattr(namespace, self.dest)
            if arr is None:
                arr = []
                setattr(namespace, self.dest, arr)
            arr.append( values )
 
    parser = argparse.ArgumentParser(description='zipdump - scan file contents for PKZIP data',
                                     epilog='zipdump can quickly scan a zip from an URL without downloading the complete archive')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='-v: print headers, -vv: print extra')
    parser.add_argument('--quiet', '-q', action='store_true', help="don't print filenames")
    parser.add_argument('--debug', action='store_true', help='print stacktrace and exit on exceptions')
    parser.add_argument('--httptrace', action='store_true', help='print http requests and responses to stdout')
    parser.add_argument('--streamdebug', action='store_true', help='debugging the (file|url)stream interface')
    parser.add_argument('--cat', '-c', type=str, action=MultipleOptions, help='decompress file to stdout')
    parser.add_argument('--raw', '-p', type=str, action=MultipleOptions, help='print raw compressed file data to stdout')
    parser.add_argument('--save', '-s', type=str, action=MultipleOptions, help='extract file to the output directory')
    parser.add_argument('--outputdir', '-d', type=str, help='the output directory, default = curdir', default='.')
    parser.add_argument('--extract', '-e', action='store_true', help='Extract all files')
    parser.add_argument('--strip', '-j', type=int, help='strip N initial parts from pathnames before saving')
    parser.add_argument('--analyze', action='store_true', help='Detailed .zip analysis, finds all PKnnn chunks.')
    parser.add_argument('--preserve', '-P',  action='store_true', help="preserve permissions and timestamps")
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('--allowdotdot', action='store_true', help='allow paths to walk outside of output directory.')

    parser.add_argument('--offset', '-o', type=str, help='start processing at offset')
    parser.add_argument('--length', '-l', type=str, help='max length of data to process')
    parser.add_argument('--chunksize', type=str, default="0x100000")
    parser.add_argument('--pretty', action='store_true', help='make output easier to read')
    parser.add_argument('--dumpraw', action='store_true', help='hexdump raw compressed data')
    parser.add_argument('--limit', type=str, help='limit raw dump output')
    parser.add_argument('--headers', '-H', type=str, help='Add custom http headers', action=MultipleOptions)

    parser.add_argument('--password', type=str, help="Password for pkzip decryption")
    parser.add_argument('--hexpassword', type=str, help="hexadecimal password for pkzip decryption")
    parser.add_argument('--keys', type=str, help="internal key representation for pkzip decryption")

    parser.add_argument('FILES', type=str, nargs='*', help='Files or URLs')
    args = parser.parse_args()

    if args.offset is not None: args.offset = int(args.offset, 0)
    if args.length is not None: args.length = int(args.length, 0)
    if args.chunksize is not None: args.chunksize = int(args.chunksize, 0)

    if args.limit:
        args.limit = int(args.limit, 0)

    if args.hexpassword:
        args.password = binascii.a2b_hex(args.hexpassword)
    elif args.keys:
        args.password = list(int(_, 0) for _ in args.keys.split(","))
    elif args.password:
        args.password = args.password.encode('utf-8')

    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):

            if len(args.FILES)>1 and not args.quiet:
                print("\n==> " + fn + " <==\n")
            try:
                if fn.find("://") in (3,4,5):
                    # when argument looks like a url, use urlstream to open
                    try:
                        # prefer urllib3 based version, this supports connection pooling.
                        import urlstream3 as urlstream
                    except ModuleNotFoundError:
                        # fall back to urllib2 based version
                        import urlstream

                    if args.httptrace:
                        urlstream.debuglog = True

                    kwargs = {'trace':args.httptrace}
                    if args.headers:
                        hdrs = dict()
                        for h in args.headers:
                            k, v = h.split(':', 1)
                            hdrs[k] = v
                        kwargs['headers'] = hdrs

                    with urlstream.open(fn, **kwargs) as fh:
                        processfile(args, fh)
                else:
                    with open(fn, "rb") as fh:
                        processfile(args, fh)
            except Exception as e:
                if args.debug:
                    raise
                print("WARNING: %s" % e)
    else:
        processfile(args, sys.stdin.buffer)


if __name__ == '__main__':
    main()
