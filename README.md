# zipdump
Analyze zipfile, either local, or from url

`zipdump` can either do a full scan, finding all PK-like headers, or it can do a quick scan ( like the usual `zip -v` type output ).

`zipdump -q`  works equally quick on web based resources as on local files.
This makes it quite easy to quickly investigate a large number of large .zip files without actually needing to download them.

I wrote this tool because i wanted to look at the contents of lots of apple ios firmware files without downloading 100s of GB of data.

For instance:

    python3 zipdump.py -q http://appldnld.apple.com/ios10.0/031-64655-20160705-A371AD14-3E3F-11E6-A58B-C84C60941A1E/com_apple_MobileAsset_SoftwareUpdate/d75e3af423ae0308a8b9e0847292375ba02e3b11.zip
  
`zipdump` needs pyton3.


Or you could extract a specific file from lots of zips using:

    cat urllist | xargs zipdump -q --cat somefile.txt

COMMANDLINE OPTIONS
===================

 * `--cat` FILENAME    will decrypt, decompress the specified filename to stdout
 * `--raw` FILENAME    will decrypt, but not decompress the specified filename to stdout
 * `--save` FILENAME   will save the decrypted, decompressed file to the output directory
 * `--outputdir` DIR   specify where to save extracted files.
 * `--quick`           will quickly scan a file, without investigating the entire file.
 * `--offset OFS --length SIZE`   specify a chunk of a file to investigate
    you can used this to list zip contents from a zip file embeded in another binary file.
 * `--dumpraw`         hexdump the entire zip file contents, optionally limiting the amount of data printed.
   * `--limit LIMIT`     limit raw dump output
 * `--keys  0x1,0x2,0x3`  specify the internal encryption key for decrypting encrypted files.
 * `--password  PASSWD `  specify the password for decrypting encrypted files.
 * `--hexpassword  HEXPASSWD `  specify the password for decrypting encrypted files.
    useful when the password is not an ascii string.

 * `--extract`         Extract all files to the `outputdir`, optionally stripping leading parts of the filename
   * `--strip STRIP`     strip N initial parts from pathnames before saving
   * `--preserve`        preserve permissions and timestamps

When searching for .zip files, you can recurse and skip links using these options:
 * `--recurse`         recurse into directories
 * `--skiplinks`       skip symbolic links

The zip file is read in `chunksize` chunks, default 1M, you can alter this using the `--chunksize` option.

Then there are several options controlling how much output is generated:
 * `--pretty`          very verbose output
 * `--verbose`
 * `--quiet`
 * `--debug`




TODO
====

 * add option to save a specific entry by index, or offset into the file.
     * this would be useful when an archive contains an entry with a difficult to type name.
 * add option to save an entry by name to a differently named file.
 * by default sanitize filenames before use, with option to disable sanitation.
 * currently XTRA is printed only when specifying --dumpraw, i would like to see this
   parsed and printed with --verbose.
 * rename pretty to 'very verbose'
 * add option to save each file to a zipfile specific subdirectory. So you can extract
   multiple files in one command.
 * support stdin
 * as library: add better interface, which allows enumeration of contents, lookup of files, extraction of files.



HISTORY
=======

This tool started out as a perl script named zipdbg in 2003.


(c) 2016 Willem Hengeveld <itsme@xs4all.nl>
