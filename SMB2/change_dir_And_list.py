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
        
        ntstatus,fileId, filesize = smb2client.create(tid,"abc","oplock=0","accessmask=1",\
                           "fileattr=128","sharemode=7","disposition=3", "createoptions=1"\
                           ,"DHNQ","MXAC","QFID")
        if ntstatus != 0:
           print "open failed"
           exit()
        ntstatus,li,cnt = smb2client.query_directory(tid, fileId, "fileinfo=1")
        print "list of files"
        while cnt>0:
            print li[cnt-1][0]
            cnt -= 1
        ntstatus = smb2client.close(tid ,fileId)
     
        ntstatus = smb2client.tree_disconnect(tid)
     
        ntstatus = smb2client.logoff()


