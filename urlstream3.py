"""
urlstream3 wraps an urlrequest in a stream-like object, which supports read, seek and 'with'.
An urlstream3 object can be used as a drop in replacement for file.open.

Usage:

    with urlstream3.open("http://example.com/largezip.zip") as fh:
         fh.seek(-22, os.SEEK_END)
         data = fh.read(22)
         print(data)

(C) 2024 Willem Hengeveld  <itsme@xs4all.nl>
"""
import sys
import re
from errno import EINVAL, ENOENT
from os import SEEK_SET, SEEK_CUR, SEEK_END
import urllib.parse
import urllib.error
import urllib3

# set this to True when debugging this module
debuglog = False

g_pool = urllib3.PoolManager()

def open(url, mode=None, trace=False, headers=None):
    """
    Use urlstream.open for doing a simple request, without customizing request headers

    'mode' is ignored, it is there to be argument compatible with file.open()
    """

    httpauth = None
    # support basic http authentication
    m = re.match(r'(\w+://)([^/]+?)(?::([^/]+))?@(.*)', url)
    if m:
        url = m.group(1)+m.group(4)
        httpauth = m.group(2) + ':' + m.group(3)

    m = re.match(r'^(\S+?://)(.*?)(\?.*)?$', url)
    if not m:
        print("unrecognized url: %s" % url)
        return
    protocol = m.group(1)
    basepath = urllib.parse.quote(m.group(2))
    query = m.group(3) or ""
    return urlstream(protocol + basepath + query, httpauth)


class urlstream(object):
    """ Urlstream requests chunks from a web resource as directed by read + seek requests """
    def __init__(self, url, auth):
        self.url = url
        self.absolutepos = 0

        kwargs = dict(keep_alive=True)
        if auth:
            kwargs['basic_auth'] = auth
        self.headers = urllib3.HTTPHeaderDict(urllib3.make_headers(**kwargs))

        self.buffer = None
        self.bufferstart = None    # position of start of buffer

        if debuglog:
            print("URL: %s" % url)

    def clearrange(self):
        """ Remove Range header from request. """
        self.headers.discard('Range')

    def next(self, size):
        """ Download next chunk. """
        # Retrieve anywhere between 64k and 1M byte
        if size is not None:
            size = min(max(size, 0x10000), 0x100000)

        if self.absolutepos < 0:
            # relative to the end of the file
            self.headers['Range'] = "bytes=%d" % self.absolutepos
        elif size is None:
            # open ended range
            self.headers['Range'] = "bytes=%d-" % (self.absolutepos)
        else:
            # fixed absolute range
            self.headers['Range'] = "bytes=%d-%d" % (self.absolutepos, self.absolutepos+size-1)


        if debuglog: print("next: ", self.headers['Range'])

        f = self.doreq('GET')
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

        if f.status==416:
            # outside of content range -> return empty
            return None

        return f.data

    def read(self, size=None):
        """ Read bytes from stream. """
        if size is None:
            if self.absolutepos==0:
                self.clearrange()
                if debuglog: print("read: entire file")
                f = self.doreq('GET')
                if debuglog:
                    print(f.headers)
                return f.data

            # read until end of file
            data = self.next(None)
            self.absolutepos += len(data)
            return data

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
        return self.absolutepos

    def tell(self):
        """ Return the current absolute position. """
        if self.absolutepos>0:
            if debuglog: print("tell -> ", self.absolutepos)
            return self.absolutepos

        self.clearrange()

        head_response = self.doreq('HEAD')
        if debuglog:
            print(head_response.headers)

        if "Content-Length" not in head_response.headers:
            raise Exception("no content-length")

        self.contentLength = int(head_response.headers.get("Content-Length"))

        self.absolutepos += self.contentLength
        return self.absolutepos

    def doreq(self, method):
        """
        Do the actual http request, translating 404 into ENOENT.

        returns a httplib.HTTPResponse object
        """
        lasterr = None
        for _ in range(4):
            try:
                return g_pool.request(method, self.url, headers=self.headers)
            except ConnectionError as err:
                if debuglog:
                    print("retrying", err)
            except urllib3.exceptions.HTTPError as err:
                if err.code==404:
                    raise IOError(ENOENT, "Not found")
                if err.code==416:
                    if debuglog:
                        print("status 416")
                    # outside of content range -> return empty
                    return err.fp
                raise
            except urllib.error.URLError as err:
                if debuglog:
                    print("retrying", err)
                lasterr = err

        raise lasterr

    # for supporting 'with'
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass
