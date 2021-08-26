# a tool for hexdumping a section of a large online file.
from __future__ import division, print_function, absolute_import, unicode_literals

import urlstream
import argparse
import os
import struct

def streamsize(fh):
    fh.seek(0, os.SEEK_END)
    return fh.tell()

def clear_lower_bits(n):
    m = 0
    while n:
        m = n
        n &= n-1
    return m

def ascchr(c):
    if c<32:
        return '.'
    if c>=127:
        return '.'
    return chr(c)

def processstream(args, fh):
    offset = args.offset or 0
    length = args.length
    endofs = args.end

    step = args.step
    maxelemsperline = args.width
    elemsize = args.elemsize or 1

    if maxelemsperline is None:
        linewidth = 110

        ofsneeded = 8   # todo: make depend on filesize
        extrawidth = 2  # ': '
        elemwidth = 0
        if args.with_hexdump:
            elemwidth += 1 + 2 * elemsize
        if args.with_ascdump:
            elemwidth += 1
        if args.with_hexdump and args.with_ascdump:
            extrawidth += 1

        # ofsneeded + extrawidth + elemcount * elemwidth <= linewidth 
        maxelemsperline = clear_lower_bits( ( linewidth - (ofsneeded + extrawidth) ) // elemwidth )

    hexwidth = (1+2*elemsize)*maxelemsperline 
    ascwidth = maxelemsperline 

#  -a    +a
#  57 /  75 oooooooo: dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  aaaaaaaaaaaaaaaa
#  49 /  67 oooooooo: dddd dddd dddd dddd dddd dddd dddd dddd  aaaaaaaaaaaaaaaa
# 105 / 139 oooooooo: dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd dd  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#  89 / 123 oooooooo: dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd dddd  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#  81 / 115 oooooooo: dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa


    ifmt = { 1:"B", 2:"H", 4:"L", 8:"Q" }
    infmt = "<%d" + ifmt[elemsize]
    outfmt = "%" + "%03dx" % (elemsize*2)

    datasize = streamsize(fh)

    if endofs is not None and endofs < 0:
        endofs += datasize
    if length is not None and length < 0:
        length += datasize
    if offset is not None and offset < 0:
        offset += datasize

    if endofs is None and length is None:
        endofs = datasize
    if endofs is None:
        endofs = offset + length

    def hexdump(offset, data):
        items = []
        items.append("%08x: " % offset)
        if args.with_hexdump:
            items.append(" ".join(outfmt % _ for _ in struct.unpack(infmt % (len(data)//elemsize), data)).ljust(hexwidth))
        if args.with_hexdump and args.with_ascdump:
            items.append("  ")
        if args.with_ascdump:
            items.append("".join(ascchr(_) for _ in struct.unpack("%dB" % len(data), data)).ljust(ascwidth))
        # todo: unicode dump
        return "".join(items)

    chunksize = maxelemsperline * elemsize

    while offset < endofs:
        fh.seek(offset)
        want = min(chunksize, endofs-offset)
        chunk = fh.read(want)
        if not chunk:
            break

        print(hexdump(offset, chunk))

        if args.step:
            offset += step
        else:
            offset += len(chunk)

def main():
    parser = argparse.ArgumentParser(description='webdump - hexdump data via HTTP',)

    parser.add_argument('-o', '--offset', type=str, help='Offset into web resource.')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-l', '--length', type=str, help='number of bytes to output')
    parser.add_argument('-e', '--end', type=str, help='Offset after last offset to process')
    parser.add_argument('-s', '--step', type=str, help='Step size')
    parser.add_argument('-w', '--width', type=str, help='nr of items per line')
    parser.add_argument('-x', action='store_const', dest='outputmode', const='hexonly', help='only hex, no asc')
    parser.add_argument('-xx', action='store_const', dest='outputmode', const='asconly', help='only asc, no hex')
    parser.add_argument('-8', action='store_const', dest='elemsize', const=8, help='output as 64 bit qwords')
    parser.add_argument('-4', action='store_const', dest='elemsize', const=4, help='output as 32 bit dwords')
    parser.add_argument('-2', action='store_const', dest='elemsize', const=2, help='output as 16 bit hwords')
    parser.add_argument('-1', action='store_const', dest='elemsize', const=1, help='output as 8 bit bytes')
    parser.add_argument('URLS', type=str, nargs='+', help='The web resources we are interested in.')
    args = parser.parse_args()

    if args.debug:
        urlstream.debuglog = True

    if args.outputmode == 'hexonly':
        args.with_hexdump = True
        args.with_ascdump = False
    elif args.outputmode == 'asconly':
        args.with_hexdump = False
        args.with_ascdump = True
    else:
        args.with_hexdump = args.with_ascdump = True

    # convert 0xHEX or DEC strings to number
    for key in ('offset', 'length', 'end', 'step', 'width'):
        if key in args and getattr(args, key) is not None:
            setattr(args, key, int(getattr(args, key), 0))
             
    for fn in args.URLS:
        if len(args.URLS)>1:
            print("==> %s <==" % fn)
        if fn.find("://") in (3,4,5):
            with urlstream.open(fn) as fh:
                processstream(args, fh)
        else:
            with open(fn, "rb") as fh:
                processstream(args, fh)

if __name__ == '__main__':
    main()
