#!/usr/bin/env python
import sys
import string

from smb2pack import config
from smb2pack import smb2
from smb2pack import constants


if __name__ == "__main__": 
        
        const = constants.smb2Constants()
        
        smb2client = smb2.SMB(config.remoteIP,config.smbport)
        
        smb2client.login(config.username, config.password)
        
        ntstatus,sid,tid = smb2client.tree_connect("\\\\"+config.remoteIP+"\\"+config.share)
        ################## 1st rename ################
        ntstatus,fileId, filesize = smb2client.create(tid,"ram.txt","oplock=0","accessmask=1114240",\
                           "fileattr=0","sharemode=7","disposition=1", "createoptions=2112"\
                           ,"DHNQ","MXAC","QFID")
        if ntstatus != 0:
        	  print "file open failed"
        	  exit()
        
        ntstatus = smb2client.set_info(tid, fileId,"infotype="+str(const.SMB2_0_INFO_FILE),\
                   "fileinfoclass="+str(const.FileRenameInformation),"replaceifexists=0","filename=test3.txt")
        if ntstatus == 0:
        	  print "file rename successful"
        else:
           print "file rename failed"
        ntstatus = smb2client.close(tid ,fileId)
        ################## 2nd rename ################
        ntstatus,fileId, filesize = smb2client.create(tid,"test3.txt","oplock=0","accessmask=1114240",\
                           "fileattr=0","sharemode=7","disposition=1", "createoptions=2112"\
                           ,"DHNQ","MXAC","QFID")
        if ntstatus != 0:
        	  print "file open failed"
        	  exit()
        
        ntstatus = smb2client.set_info(tid, fileId,"infotype="+str(const.SMB2_0_INFO_FILE),\
                   "fileinfoclass="+str(const.FileRenameInformation),"replaceifexists=0","filename=ram.txt")
        if ntstatus == 0:
        	  print "file rename successful"
        else:
           print "file rename failed"
        ntstatus = smb2client.close(tid ,fileId)
        
        
        
        ntstatus = smb2client.tree_disconnect(tid)
        
        ntstatus = smb2client.logoff()


