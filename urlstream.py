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
from os import SEEK_SET, SEEK_CUR, SEEK_END
if sys.version_info[0] == 3:
    import urllib.request
    from urllib.request import Request
    urllib2 = urllib.request

    import urllib.parse
    urllib2.quote = urllib.parse.quote
else:
    import urllib2
    from urllib2 import Request

# add urlopen method to request object, so later we don't need
# to explicitly know the name of the urllib2 module.
Request.urlopen = urllib2.urlopen

# set this to True when debugging this module
debuglog = False

def open(url, mode=None):
    """
    Use urlstream.open for doing a simple request, without customizing request headers

    'mode' is ignored, it is there to be argument compatible with file.open()
    """

    # support basic http authentication
    m = re.match(r'(\w+://)([^/]+?)(?::([^/]+))?@(.*)', url)
    if m:
        url = m.group(1)+m.group(4)
        authinfo = urllib2.HTTPPasswordMgrWithDefaultRealm()
        authinfo.add_password(None, url, m.group(2), m.group(3))
        urllib2.install_opener(urllib2.build_opener(urllib2.HTTPBasicAuthHandler(authinfo)))

    # todo: only re-encode when the url does not have '%xx' chars in it.
    m = re.match(r'^(\S+?://)(.*?)(\?.*)?$', url)
    if not m:
        print("unrecognized url: %s" % url)
        return
    method = m.group(1)
    basepath = urllib2.quote(m.group(2))
    query = m.group(3) or ""
    return urlstream(Request(method + basepath + query))


class urlstream(object):
    """ Urlstream requests chunks from a web resource as directed by read + seek requests """
    def __init__(self, req):
        """ Construct a urlstream object given a urllib.Request object. """
        self.req = req
        self.absolutepos = 0

        self.buffer = None
        self.bufferstart = None    # position of start of buffer

        if debuglog:
            print("URL: %s" % req.get_full_url())

    def clearrange(self):
        """ Remove Range header from request. """
        if hasattr(self.req, 'remove_header'):
            # python3
            self.req.remove_header('Range')
        else:
            # python2
            self.req.headers.pop('Range', None)

    def next(self, size):
        """ Download next chunk. """
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
        if debuglog:
            print(f.headers)

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

        if f.code==416:
            # outside of content range -> return empty
            return None

        return f.read()

    def read(self, size=None):
        """ Read bytes from stream. """
        if size is None:
            if self.absolutepos==0:
                self.clearrange()
                if debuglog: print("read: entire file")
                f = self.doreq()
                if debuglog:
                    print(f.headers)
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

    def seek(self, size, whence=SEEK_SET):
        """ Seek to a different offset. """
        if debuglog: print("seek", size, whence)
        if whence == SEEK_SET and size>=0:
            self.absolutepos = size
        elif whence == SEEK_CUR:
            self.absolutepos += size
        elif whence == SEEK_END and size<=0:
            self.absolutepos = size
        else:
            raise IOError(EINVAL, "Invalid seek arguments")

        if self.buffer and not self.bufferstart <= self.absolutepos < self.bufferstart+len(self.buffer):
            self.buffer = None
            self.bufferstart = None

    def tell(self):
        """ Return the current absolute position. """
        if self.absolutepos>0:
            if debuglog: print("tell -> ", self.absolutepos)
            return self.absolutepos

        # note: with python3 i could have used the 'method' property
        saved_method = self.req.get_method
        self.req.get_method = lambda : 'HEAD'
        if debuglog: print("tell: HEAD")
        self.clearrange()

        try:
            head_response = self.doreq()
            if debuglog:
                print(head_response.headers)
            result = head_response.getcode()
        except:
            # restore get_method, irrespective of the type of error.
            self.req.get_method = saved_method
            raise

        self.req.get_method = saved_method

        self.contentLength = int(head_response.headers.get("Content-Length"))

        self.absolutepos += self.contentLength
        return self.absolutepos

    def doreq(self):
        """
        Do the actual http request, translating 404 into ENOENT.

        returns a httplib.HTTPResponse object
        """
        try:
#            return urllib2.urlopen(self.req)
            return self.req.urlopen()
        except urllib2.HTTPError as err:
            if err.code==404:
                raise IOError(ENOENT, "Not found")
            if err.code==416:
                if debuglog:
                    print("status 416")
                # outside of content range -> return empty
                return err.fp
            raise

    # for supporting 'with'
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass
