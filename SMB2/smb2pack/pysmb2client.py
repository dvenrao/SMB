#!/usr/bin/env python
#import thread
#import sys
#import time
#import threading
#import socket, struct, os
import ConfigParser
import string
import constants

from smbconnect import smbConnect
import smb2
if __name__ == "__main__": 

        config = ConfigParser.ConfigParser()
        const = constants.smb2Constants()
        config.read('smb2setup.cfg')
        remoteIP = config.get('setup', 'cifsserverip')
        smbport = config.get('setup', 'port')
        username =  config.get('setup', 'username')
        password = config.get('setup', 'password')
        share = config.get('setup', 'sharename')

        smb2client = smb2.SMB(remoteIP,smbport)
        smb2client.login(username, password)
        ntstatus,sid,tid = smb2client.tree_connect("\\\\"+remoteIP+"\\"+share)

#        print const.SMB2_0_INFO_SECURITY   
        ntstatus,fileId, filesize = smb2client.create(tid,"ram.txt","oplock=0","accessmask=7",\
                           "fileattr=128","sharemode=7","disposition=1", "createoptions=2112","DHNQ","MXAC","QFID")
#        ntstatus,fileId, filesize = smb2client.create(tid,"test5","oplock=0","accessmask=7",\
#                           "fileattr=128","sharemode=7","disposition=2", "createoptions=23","DHNQ","MXAC","QFID")
##        ntstatus,fileId, filesize = smb2client.create(tid,"test5","oplock=0","accessmask=7",\
##                           "fileattr=128","sharemode=7","disposition=1", "createoptions=23","DHNQ","MXAC","QFID")
        ntstatus = smb2client.read(tid, fileId, filesize, "offset=1", "length=112")
#        smb2client.read(tid, fileId, filesize, "offset=1", "length=78689")

##        ntstatus = smb2client.write(tid, fileId, "offset=10","data = welcome")
#        smb2client.write(tid, fileId, "offset=0","data = hello welcome hello welcome hello welcome hello welcome")
#        smb2client.write(tid, fileId, "offset=100","data = as;a sa; sa;s;as ;as;a;sa;sa;s;a")
##        ntstatus,li,cnt = smb2client.query_directory(tid, fileId, "fileinfo=1")
##        print li[0][0]
        ntstatus = smb2client.query_info(tid, fileId,"infotype="+str(const.SMB2_0_INFO_FILE),\
                    "fileinfoclass="+str(const.FileStandardInformation))
##        ntstatus = smb2client.set_info(tid, fileId,"infotype="+const.SMB2_0_INFO_FILE,\
##                   "fileinfoclass="+const.FileAllocationInformation)
###        ntstatus = smb2client.set_info(tid, fileId,"infotype="+const.SMB2_0_INFO_FILESYSTEM,\
###                   "fileinfoclass="+const.FileFsControlInformation)
###        ntstatus = smb2client.set_info(tid, fileId,"infotype="+const.SMB2_0_INFO_SECURITY,\
###                   "AdditionalInformation="+const.OWNER_SECURITY_INFORMATION)
###        ntstatus = smb2client.set_info(tid, fileId,"infotype="+const.SMB2_0_INFO_QUOTA,\
###                   ")
#        ntstatus = smb2client.change_notify(tid, fileId)
#        ntstatus = smb2client.lock(tid, fileId)
#        ntstatus = smb2client.ioctl(tid, fileId)
#        ntstatus = smb2client.oplock_break(tid, fileId)
        ntstatus = smb2client.close(tid ,fileId)
        ntstatus = smb2client.tree_disconnect(tid)
        ntstatus = smb2client.logoff()

        
		
		
#        smb2client.flush(fileId)
#        smb2client.cancel(msgId)


#    try:
#        while 1:
#            continue
#    except:
#        print '' #
		        
