# zipdump
Analyze zipfile, either local, or from url

`zipdump` can either do a full scan, finding all PK-like headers, or it can do a quick scan ( like the usual `zip -v` type output ).

`zipdump -q`  works equally quick on web based resources as on local files.
This makes it quite easy to quickly investigate a large number of large .zip files without actually needing to download them.

I wrote this tool because i wanted to look at the contents of lots of apple ios firmware files without downloading 100s of GB of data.

For instance:

    python zipdump.py -q http://appldnld.apple.com/ios10.0/031-64655-20160705-A371AD14-3E3F-11E6-A58B-C84C60941A1E/com_apple_MobileAsset_SoftwareUpdate/d75e3af423ae0308a8b9e0847292375ba02e3b11.zip
  
`zipdump` works with both python2 and pyton3.


(c) 2016 Willem Hengeveld <itsme@xs4all.nl>
