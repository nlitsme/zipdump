import struct
import crcmod.predefined
crc32 = crcmod.predefined.mkPredefinedCrcFun('crc-32')
"""
Construct zip files with various kinds of bad behaviour.

Current:
      - vary long paths
      - paths with ..
      - paths pointing to symlinks.
"""

def getdottedpath(i):
    p = ""
    while i:
        p += "/" + "." * (i%3)
        i //= 3
    return p[1:] or '/'

class Writer:
    def __init__(self, fh):
        self.fh = fh
    def tell(self):
        return self.fh.tell()
    def write(self, data):
        self.fh.write(data)
    def write16le(self, val):
        self.write(struct.pack("<H", val))
    def write32le(self, val):
        self.write(struct.pack("<L", val))

class FileEnt:
    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.crc = crc32(data)
        self.xattr = b""
        self.islink = False

    def encode(self, w):
        w.write(b"PK\x03\x04")
        w.write16le(10)  # need
        w.write16le(0)   # flags
        w.write16le(0)   # method
        w.write32le(0x571658d4) # stamp
        w.write32le(self.crc)
        w.write32le(len(self.data)) # compsize
        w.write32le(len(self.data)) # fullsize
        w.write16le(len(self.name))   # namelen
        w.write16le(len(self.xattr))   # xlen
        w.write(self.name)
        w.write(self.xattr)
        w.write(self.data)

class DirEnt:
    def __init__(self, name, crc, datalen):
        self.name = name
        self.crc = crc
        self.datalen = datalen
        self.osattr = 0o100644<<16
        self.xattr = b""
    def makedir(self):
        self.osattr = (0o040755<<16)  + 0x10
    def makelink(self):
        self.osattr = 0o120777<<16

    def encode(self, w):
        w.write(b"PK\x01\x02")
        w.write16le(0x31e)  # crea
        w.write16le(10)  # need
        w.write16le(0)   # flags
        w.write16le(0)   # method
        w.write32le(0x571658d4) # stamp
        w.write32le(self.crc)
        w.write32le(self.datalen) # compsize
        w.write32le(self.datalen) # fullsize
        w.write16le(len(self.name))   # namelen
        w.write16le(len(self.xattr))   # xlen
        w.write16le(0)   # clen
        w.write16le(0)   # dsk0
        w.write16le(0)   # atr
        w.write32le(self.osattr)
        w.write32le(self.dataptr)
        w.write(self.name)
        w.write(self.xattr)

class EODEnt:
    def __init__(self, nrentries, dirsize, diroffset):
        self.nrentries = nrentries
        self.dirsize = dirsize
        self.diroffset = diroffset
    def encode(self, w):
        w.write(b"PK\x05\x06")
        w.write16le(0)  # diskid
        w.write16le(0)  # diskstart
        w.write16le(self.nrentries)
        w.write16le(self.nrentries)
        w.write32le(self.dirsize)
        w.write32le(self.diroffset)
        w.write16le(0)  # comment size

class Zipfile:
    def __init__(self):
        self.entries = []
    def addfile(self, name, src):
        if type(src)==bytes:
            data = src
        elif type(src)==str:
            data = src.encode('utf-8')
        elif hasattr(src, 'read'):
            data = src.read()
        else:
            raise Exception(f"dont know how to read {src}")

        self.entries.append(FileEnt(name.encode('utf-8'), data))

    def addsymlink(self, name, dst):
        e = FileEnt(name.encode('utf-8'), dst.encode('utf-8'))
        e.islink = True
        self.entries.append(e)

    def save(self, w):
        for e in self.entries:
            o = w.tell()
            e.dataptr = o
            e.encode(w)
        dirofs = w.tell()
        for e in self.entries:
            de = DirEnt(e.name, e.crc, len(e.data))
            de.dataptr = e.dataptr
            if e.islink:
                de.makelink()
            de.encode(w)
        dirend = w.tell()
        eod = EODEnt(len(self.entries), dirend-dirofs, dirofs)
        eod.encode(w)


def oldmakezip(zipfilename):
    z = Zipfile()
    for i in range(27):
        # create symlinks
        z.addsymlink(f"s{i:02d}", getdottedpath(i))

    for i in range(27):
        # file in symlinked dir
        z.addfile(f"s{i:02d}/badfile_1{i:02d}.txt", b"")

        # file with dotted path directly
        p = getdottedpath(i)
        z.addfile(f"{p}/badfile_2{i:02d}.txt", b"")

    for l in range(230, 270):
        # long filename
        z.addfile(f"{l+3+4}{'x'*l}.txt", b"")
        # long dirname
        z.addfile(f"{l+3}{'y'*l}/x.txt", b"")

    with open(zipfilename, "wb") as fh:
        z.save(Writer(fh))

def zipgenerators():
    for i in range(27):
        # create symlinks
        yield lambda z: z.addsymlink(f"s{i:02d}", getdottedpath(i))

    for i in range(27):
        # file in symlinked dir
        yield lambda z:z.addfile(f"s{i:02d}/badfile_1{i:02d}.txt", b"")

        # file with dotted path directly
        p = getdottedpath(i)
        yield lambda z:z.addfile(f"{p}/badfile_2{i:02d}.txt", b"")

    for l in range(230, 270):
        # long filename
        yield lambda z:z.addfile(f"{l+3+4}{'x'*l}.txt", b"")
        # long dirname
        yield lambda z:z.addfile(f"{l+3}{'y'*l}/x.txt", b"")


def makezip(zipfilename):
    z = Zipfile()
    for gen in zipgenerators():
        gen(z)
    with open(zipfilename, "wb") as fh:
        z.save(Writer(fh))


def makezips(zipbase):
    for i, gen in enumerate(zipgenerators()):
        z = Zipfile()
        gen(z)
        with open(f"{zipbase}-{i:04d}.zip", "wb") as fh:
            z.save(Writer(fh))


def main():
    makezip("escapedzip.zip")
    makezips("esc")

if __name__=='__main__':
    main()
