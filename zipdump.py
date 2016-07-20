#!/usr/local/bin/python3
"""
Analyze PKZIP file contents

 * scan entire file for PKxy headers
 * do quick scan by locating EOF header
 * can operate on .zip files from a http://URL

(C) 2016 Willem Hengeveld  <itsme@xs4all.nl>
"""
from __future__ import division, print_function, absolute_import, unicode_literals
import sys
import os
import binascii
import struct
import datetime
if sys.version_info[0] == 2:
    import scandir
    os.scandir = scandir.scandir


class EntryBase(object):
    """ base class for PK headers """
    def loaditems(self, fh):
        """ loads any items refered to by the header """
        pass


######################################################
#  Decoder classes
######################################################

class CentralDirEntry(EntryBase):
    HeaderSize = 42
    MagicNumber = b'\x01\x02'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.createVersion, self.neededVersion, self.flags, self.method, self.timestamp, \
            self.crc32, self.compressedSize, self.originalSize, self.nameLength, self.extraLength, \
            self.commentLength, self.diskNrStart, self.zipAttrs, self.osAttrs, self.dataOfs = \
            struct.unpack_from("<4H4L5HLL", data, ofs)
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
        self.name = fh.read(self.nameLength).decode("utf-8", "ignore")
        fh.seek(self.extraOffset)
        self.extra = fh.read(self.extraLength)
        fh.seek(self.commentOffset)
        self.comment = fh.read(self.commentLength).decode("utf-8", "ignore")

    def summary(self):
        def flagdesc(fl):
            if fl&64: return "AES"
            if fl&1: return "CRYPT"
            return ""
        return "%10d (%5.1f%%)  %s  %08x [%5s] %s" % (
                self.originalSize,
                100.0*self.compressedSize/self.originalSize if self.originalSize else 0,
                datetime.datetime.utcfromtimestamp(self.timestamp),
                self.crc32,
                flagdesc(self.flags),
                self.name
                )

    def __repr__(self):
        r = "PK.0102: %04x %04x %04x %04x %08x %08x %08x %08x %04x %04x %04x %04x %04x %08x %08x |  %08x %08x %08x %08x" % (
            self.createVersion, self.neededVersion, self.flags, self.method, self.timestamp,
            self.crc32, self.compressedSize, self.originalSize, self.nameLength, self.extraLength,
            self.commentLength, self.diskNrStart, self.zipAttrs, self.osAttrs, self.dataOfs,
            self.nameOffset, self.extraOffset, self.commentOffset, self.endOffset)
        if self.name:
            r += " - " + self.name
        if self.comment:
            r += "\n" + self.comment
        return r


class LocalFileHeader(EntryBase):
    HeaderSize = 26
    MagicNumber = b'\x03\x04'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.neededVersion, self.flags, self.method, self.timestamp, self.crc32, \
            self.compressedSize, self.originalSize, self.nameLength, self.extraLength = \
            struct.unpack_from("<3H4LHH", data, ofs)
        ofs += self.HeaderSize

        self.nameOffset = baseofs + ofs
        ofs += self.nameLength

        self.extraOffset = baseofs + ofs
        ofs += self.extraLength

        self.dataOffset = baseofs + ofs
        ofs += self.compressedSize

        self.endOffset = baseofs + ofs

        self.name = None
        self.extra = None
        self.data = None

    def loaditems(self, fh):
        fh.seek(self.nameOffset)
        self.name = fh.read(self.nameLength).decode("utf-8", "ignore")
        fh.seek(self.extraOffset)
        self.extra = fh.read(self.extraLength)
        # not loading data

    def __repr__(self):
        r = "PK.0304: %04x %04x %04x %08x %08x %08x %08x %04x %04x |  %08x %08x %08x %08x" % (
            self.neededVersion, self.flags, self.method, self.timestamp, self.crc32,
            self.compressedSize, self.originalSize, self.nameLength, self.extraLength,
            self.nameOffset, self.extraOffset, self.dataOffset, self.endOffset)
        if self.name:
            r += " - " + self.name
        return r


class EndOfCentralDir(EntryBase):
    HeaderSize = 18
    MagicNumber = b'\x05\x06'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.thisDiskNr, self.startDiskNr, self.thisEntries, self.totalEntries, self.dirSize, self.dirOffset, self.commentLength = \
            struct.unpack_from("<4HLLH", data, ofs)
        ofs += self.HeaderSize

        self.commentOffset = baseofs + ofs
        ofs += self.commentLength

        self.endOffset = baseofs + ofs

        self.comment = None

    def loaditems(self, fh):
        fh.seek(self.commentOffset)
        self.comment = fh.read(self.commentLength)
        if self.comment.startswith(b'signed by SignApk'):
            self.comment = repr(self.comment[:17]) + str(binascii.b2a_hex(self.comment[18:]), 'ascii')
        else:
            self.comment = self.comment.decode('utf-8', 'ignore')

    def __repr__(self):
        r = "PK.0506: %04x %04x %04x %04x %08x %08x %04x |  %08x %08x" % (
            self.thisDiskNr, self.startDiskNr, self.thisEntries, self.totalEntries, self.dirSize, self.dirOffset, self.commentLength,
            self.commentOffset, self.endOffset)
        if self.comment:
            r += "\n" + self.comment
        return r


class DataDescriptor(EntryBase):
    HeaderSize = 12
    MagicNumber = b'\x07\x08'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4

        self.crc, self.compSize, self.uncompSize = \
            struct.unpack_from("<3L", data, ofs)
        ofs += self.HeaderSize

        self.endOffset = baseofs + ofs

    def __repr__(self):
        return "PK.0708: %08x %08x %08x |  %08x" % (
            self.crc, self.compSize, self.uncompSize,
            self.endOffset)


# todo
class Zip64EndOfDir(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x06\x06'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4


class Zip64EndOfDirLocator(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x06\x07'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4


class ExtraEntry(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x06\x08'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4


class SpannedArchive(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x03\x03'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4


class ArchiveSignature(EntryBase):
    HeaderSize = 0
    MagicNumber = b'\x05\x05'

    def __init__(self, baseofs, data, ofs):
        self.pkOffset = baseofs + ofs - 4


def getDecoderClass(typ):
    """ return Decoder class for the PK type """
    for cls in (CentralDirEntry, LocalFileHeader, EndOfCentralDir, DataDescriptor, Zip64EndOfDir, Zip64EndOfDirLocator, ExtraEntry, SpannedArchive, ArchiveSignature):
        if cls.MagicNumber == typ:
            return cls


def findPKHeaders(args, fh):
    """ scan entire file for PK headers """

    def processchunk(o, chunk):
        n = -1
        while True:
            n = chunk.find(b'PK', n+1)
            if n == -1 or n+4 > len(chunk):
                break
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


def scanzip(args, fh):
    """ do a quick scan of the .zip file, starting by locating the EOD marker """
    # 100 bytes is the smallest .zip possible
    fh.seek(-100, 2)

    eoddata = fh.read()
    iEND = eoddata.find(b'PK\x05\x06')
    if iEND==-1:
        # try with larger chunk
        ofs = max(fh.tell()-0x10100, 0)
        fh.seek(ofs, 0)
        eoddata = fh.read()
        iEND = eoddata.find(b'PK\x05\x06')
        if iEND==-1:
            print("expected PK0506 - probably not a PKZIP file")
            return
    else:
        ofs = fh.tell()-0x100
    eod = EndOfCentralDir(ofs, eoddata, iEND+4)
    dirofs = eod.dirOffset
    print(repr(eod))

    for _ in range(eod.thisEntries):
        fh.seek(dirofs)
        dirdata = fh.read(46)
        if dirdata[:4] != b'PK\x01\x02':
            print("expected PK0102")
            return
        d = CentralDirEntry(dirofs, dirdata, 4)

        fh.seek(d.nameOffset)
        d.name = fh.read(d.nameLength).decode("utf-8", "ignore")

        if args.verbose:
            print(repr(d))
        else:
            print(d.summary())

        dirofs = d.endOffset


def processfile(args, fh):
    """ process one opened file / url """
    if args.quick:
        scanzip(args, fh)
    else:
        for entry in findPKHeaders(args, fh):
            entry.loaditems(fh)
            print("%08x: %s" % (entry.pkOffset, entry))


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
    parser = argparse.ArgumentParser(description='zipdump - scan file contents for PKZIP data',
                                     epilog='zipdump can quickly scan a zip from an URL without downloading the complete archive')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--cat', '-c', type=str, help='decompress file to stdout')
    parser.add_argument('--print', '-p', type=str, help='print raw file data to stdout')
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('--offset', '-o', type=int, help='start processing at offset')
    parser.add_argument('--length', '-l', type=int, help='max length of data to process')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick dir scan. This is quick with URLs as well.')
    parser.add_argument('--chunksize', type=int, default=1024*1024)
    parser.add_argument('FILES', type=str, nargs='*', help='Files or URLs')
    args = parser.parse_args()

    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):
            print("==> ", fn, " <==")
            try:
                if fn.find("://") in (3,4,5):
                    # when argument looks like a url, use urlstream to open
                    import urlstream
                    with urlstream.open(fn) as fh:
                        processfile(args, fh)
                else:
                    with open(fn, "rb") as fh:
                        processfile(args, fh)
            except Exception as e:
                print("ERROR: %s" % e)
                raise
    else:
        processfile(args, sys.stdin.buffer)

if __name__ == '__main__':
    main()
