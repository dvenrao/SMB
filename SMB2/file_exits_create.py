#!/usr/bin/env python
import sys
import string

from smb2pack import config
from smb2pack import smb2
from smb2pack import constants


if __name__ == "__main__": 
        

        smb2client = smb2.SMB(config.remoteIP,config.smbport)
        
        smb2client.login(config.username, config.password)
        
        ntstatus,sid,tid = smb2client.tree_connect("\\\\"+config.remoteIP+"\\"+config.share)
        
        ntstatus,fileId, filesize = smb2client.create(tid,"ram1.txt","oplock=0","accessmask=7",\
                           "fileattr=128","sharemode=7","disposition=2", "createoptions=2112"\
                           ,"DHNQ","MXAC","QFID")
                           
        if ntstatus == 0xc0000035L:
           print "File Already exits"
        else:
           print "File created"
           ntstatus = smb2client.close(tid ,fileId)
        
        ntstatus = smb2client.tree_disconnect(tid)
        
        ntstatus = smb2client.logoff()


