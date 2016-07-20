"""
urlstream wraps an urlrequest in a stream-like object, which supports read, seek and 'with'.
An urlstream object can be used as a drop in replacement for file.open.

Works with python2 and python3

Usage:

    with urlstream.open("http://example.com/largezip.zip") as fh:
         fh.seek(-22, os.SEEK_END)
         data = fh.read(22)
         print(data)

(C) 2016 Willem Hengeveld  <itsme@xs4all.nl>
"""
import sys
import re
from errno import EINVAL, ENOENT
if sys.version_info[0] == 3:
    import urllib.request
    from urllib.request import Request
    urllib2 = urllib.request
else:
    import urllib2
    from urllib2 import Request

# set this to True when debugging this module
debuglog = False

def open(url, mode=None):
    """
    Use urlstream.open for doing a simple request, without customizing request headers

    'mode' is ignored, it is there to be argument compatible with file.open()
    """
    return urlstream(Request(url))


class urlstream(object):
    """ urlstream requests chunks from a web resource as directed by read + seek requests """
    def __init__(self, req):

        self.req = req
        self.absolutepos = 0

        self.buffer = None
        self.bufferstart = None    # position of start of buffer

    def clearrange(self):
        """ remove Range header from request """
        if hasattr(self.req, 'remove_header'):
            # python3
            self.req.remove_header('Range')
        else:
            # python2
            self.req.headers.pop('Range',None)

    def next(self, size):
        """ download next chunk """
        # Retrieve anywhere between 64k and 1M byte
        if size is not None:
            size = min(max(size, 0x10000), 0x100000)

        if self.absolutepos < 0:
            # relative to the end of the file
            self.req.headers['Range'] = "bytes=%d" % self.absolutepos
        elif size is None:
            # open ended range
            self.req.headers['Range'] = "bytes=%d-" % (self.absolutepos)
        else:
            # fixed absolute range
            self.req.headers['Range'] = "bytes=%d-%d" % (self.absolutepos, self.absolutepos+size-1)


        if debuglog: print("next: ", self.req.headers['Range'])

        f = self.doreq()

        # note: Content-Range header has actual resulting range.
        # the format of the Content-Range header:
        #  
        # Content-Range: bytes (\d+)-(\d+)/(\d+)
        #  
        if self.absolutepos < 0:
            crange = f.headers.get('Content-Range')
            if crange:
                m = re.match(r'bytes\s+(\d+)-', crange)
                if m:
                    self.absolutepos = int(m.group(1))

        return f.read()

    def read(self, size=None):
        """ read bytes from stream """
        if size is None:
            if self.absolutepos==0:
                self.clearrange()
                if debuglog: print("read: entire file")
                f = self.doreq()
                return f.read()

            # read until end of file
            return self.next(None)

        # read chunk until size bytes received
        data = b""
        while size > 0:
            if self.buffer is None:
                self.buffer = self.next(size)
                self.bufferstart = self.absolutepos
            if self.buffer is None:
                return data
            slicestart = self.absolutepos - self.bufferstart
            want = min(size, len(self.buffer)-slicestart)
            sliceend = slicestart+want
            data += self.buffer[slicestart:sliceend]
            if sliceend == len(self.buffer):
                self.buffer = None
                self.bufferstart = None

            self.absolutepos += want
            size -= want

        return data

    def seek(self, size, whence=0):
        """ seek to a different offset """
        if debuglog: print("seek", size, whence)
        if whence == 0 and size>=0:
            self.absolutepos = size
        elif whence == 1:
            self.absolutepos += size
        elif whence == 2 and size<0:
            self.absolutepos = size
        else:
            raise IOError(EINVAL, "Invalid seek arguments")

        if self.buffer and not self.bufferstart <= self.absolutepos < self.bufferstart+len(self.buffer):
            self.buffer = None
            self.bufferstart = None

    def tell(self):
        """ return current absolute position """
        if self.absolutepos>=0:
            if debuglog: print("tell -> ", self.absolutepos)
            return self.absolutepos

        # note: with python3 i could have used the 'method' property
        saved_method = self.req.get_method
        self.req.get_method = lambda : 'HEAD'
        if debuglog: print("tell: HEAD")
        self.clearrange()

   
        try:
            head_response = self.doreq()
            result = head_response.getcode()
        except urllib2.HTTPError as err:
            self.req.get_method = saved_method
            raise

        self.req.get_method = saved_method

        self.contentLength = int(head_response.headers.get("Content-Length"))

        self.absolutepos += self.contentLength
        return self.absolutepos

    def doreq(self):
        """ do the actual http request, translating 404 into ENOENT """
        try:
            return urllib2.urlopen(self.req)
        except urllib2.HTTPError as err:
            if err.code!=404:
                raise
            raise IOError(ENOENT, "Not found")

    # for supporting 'with'
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass
