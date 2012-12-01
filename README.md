SMB2
====

CIFS / SMB2 client in python, Python SMB2 client

What is pysmb2client?
====================

This is a python smbclient that can generate smb/cifs request by reading the commands
from the testscript.  This client can be used with either with Windows/Samba CIFS server 
or CIFS proxy.  

Why pysmbclient?
================

This client helps in reducing the on-wire packets compared to the Windows CIFS client.
The client capabilities can also be configured.

Features in pysmbclient
=======================

1) SMB Version 2 is supported
2) Supports NTLMV1 authentication ( without extended security )
3) Supports both ports 139 and 445
4) Generates CIFS/SMB2 packets used in latest Windows Operating systems 
   (XP and higher).
5) All commands can either use absolute path to the filename or fd number. Every   file has a fd number associated with it. The fd number can be found either 
   by counting the occurance of nt_create/nt_open commands in the test script. 
   Note: File fd number starts with 0


Limitations:
============

1) File operations are considered to be operated on a single data volume.


Packages to install for using pysmbclient 
=========================================

Following python modules have to be installed for using the pysmbclient.

a) Windows:
   -------
   Python 2.6 [ complete installation ]
   pycrypto-2.0.1.win32-py2.6.exe


b) Linux:
   ------
   Python 2.6/python 2.4
   Python unicodedata module
   Python Crypt module


Setup
=====

Populate smbsetup.cfg with appropriate details before using pysmblcient.

The smbsetup.cfg can be divided into 
1) Connection settings 
    a) CIFS server/proxy IP address 
    b) Port
    c) User credentials 
    d) Authentication mode

2) Client Capabilites
    a) Unicode
    b) Longname in Request/Response
    c) 32 bit status code
    d) Oplock Level 2 supported.
