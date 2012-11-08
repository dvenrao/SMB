#!/usr/bin/env python


#
# pysmbclient.py
# SMBClient
#

import thread
import sys
import time
import threading
import socket, struct, os

##project based imports
from smb import *

if __name__ == "__main__":

    if ( len(sys.argv) != 2 ):
        print 'Usage: pysmbclient.py [testfile]'
             
    smbclient = SMB(sys.argv[1])

    if ( 0 == smbclient.connectToServer() ):
        print 'Connection to server %s failed' %smbclient.remoteName
        smbclient.logger.log("Connection to server %s failed " %smbclient.remoteName)
        
    thread.start_new_thread(smbclient.parse_test_script,())
    thread.start_new_thread(smbclient.dataReceived,())  

    try:
        while 1:
            continue
    except:
        print '' #client_socket.close()        
