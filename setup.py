from setuptools import setup


name = 'zipdump'
version = '0.4'


setup(name=name,
    version=version,
    url='https://github.com/nlitsme/zipdump',
    author='Willem Hengeveld',
    author_email='itsme@xs4all.nl',
    description='Analyze zipfile, either local, or from url',
    long_description = """
    With zipfile you can list the contents or extract files from online resources,
    without downloading the entire .zip file. This is useful when investigating
    large numbers of large downloadable files, like for instance apple's .ipsw
    firmware images.

    zipfile can also 'deep' analyze a file and find all PKZIP magic numbers in that file.
    """
    classifiers=[
        "Programming Language :: Python",
    ],
    entry_points = {
        'console_scripts': [
            'zipdump=zipdump:main',
            'webdump=webdump:main',
        ],
    },
    py_modules = [ 'urlstream', 'zipdump', 'webdump' ],
    python_requires = '>=3.7',
    classifiers = [
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Topic :: Utilities',
    ],
    license = "MIT",
    keywords = "pkzip remote network",
    zip_safe=False,

)
