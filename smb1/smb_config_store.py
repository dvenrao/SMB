#!/usr/bin/env python

import os
import pdb

CREATE_TIME     = 12
ACCESS_TIME     = 13
MODIFY_TIME     = 14
FILE_SIZE       = 15
FILE_BLK_SIZE   = 16


class NtFileInfo:
    """Contains information about the shared file/directory
    """

    def __init__(self, file_long_name='', file_short_name ='', ctime=0, atime =0,
        mtime=0, chgtime=0, filesize=0, allocsize=1024, attribs=0, ipcstate=0,
        filetype=-1):
        self.ctime_ = ctime
        self.atime_ = atime
        self.mtime_ = mtime
        self.chgtime_ = chgtime
        self.filesize_ = filesize
        self.allocsize_ = allocsize
        self.attribs_ = attribs
        self.ipcstate_ =ipcstate
        self.filetype_ = filetype
        try:
            self.shortName_ = file_short_name[:string.index(file_short_name, '\0')]
        except ValueError:
            self.shortName_ = file_short_name
        try:
            self.longName_ = file_long_name[:string.index(file_long_name, '\0')]
        except ValueError:
            self.longName_ = file_long_name

    def get_ctime(self):
        return self.ctime_

    def get_ctime_epoch(self):
        return self.smbtime_to_utc(self.ctime_)

    def get_mtime(self):
        return self.mtime_

    def get_mtime_epoch(self):
        return self.smbtime_to_utc(self.mtime_)

    def get_atime(self):
        return self.atime_

    def get_atime_epoch(self):
        return self.smbtime_to_utc(self.atime_)

    def get_filesize(self):
        return self.filesize_

    def get_allocsize(self):
        return self.allocsize_

    def checkAttribs(self, flag):
        return self.attribs_ & flag

    def isArchive(self):
        return self.checkAttribs(ATTR_ARCHIVE)
    
    def isCompressed(self):
        return self.checkAttribs(ATTR_COMPRESSED)

    def isNormal(self):
        return self.checkAttribs(ATTR_NORMAL)

    def isHidden(self):
        return self.checkAttribs(ATTR_HIDDEN)

    def isReadOnly(self):
        return self.checkAttribs(ATTR_READONLY)

    def isTemporary(self):
        return self.checkAttribs(ATTR_TEMPORARY)

    def isDirectory(self):
        return self._checkAttribs(ATTR_DIRECTORY)

    def isSystem(self):
        return self._checkAttribs(ATTR_SYSTEM)

    def __repr__(self):
        return '<SharedFile instance: file_short_name="' + self.shortName_ + '", file_long_name="' + self.longName_ + '", filesize=' + str(self.filesize_) + '>'


#Generice functions to add /delete and from a set

def add_to_request_list(RequestList, mid, list):
    if mid in RequestList:
        return 0
    t_list = { mid: list }
    RequestList.update(t_list)
    return 1

def del_from_request_list(RequestList,mid):
    if RequestList.has_key(mid):
        RequestList.pop(mid)
        return 1
    return 0

def get_value_from_request_list(RequestList,mid):
    if mid in RequestList:
        return 1, RequestList.get(mid)
    return 0, []

def find_mid_in_request_list(RequestList, mid):
    if mid in RequestList:
        return 1
    return 0

def join(server, *path):
    return '\\\\' + server + '\\' + '\\'.join(path)
    

TID_SL = 0x0000
SHARENAME = 0x0001
SHAREPATH_SL = 0x0002
SERVICE_SL = 0x0003
FILE_SYSTEM_SL = 0x0004
OPTIONAL_SUPPORT = 0x0005
SERVERIP = 0x0006

class SMBShare:
    """Contains information about a SMB share 
    """
##    tid, share, sharepath,service
    def __init__(self ):
        self.share_list = [['tid', 'sharename','sharepath',
                            'service', 'filesystem', 'optional_support',
                            'serverip']]
        self.share_list_count = 1
        
    def list_add(self, list):
        if len(list) != len(self.share_list[0]):
            print 'Error: Missing arguments'
            return 0
        
        list[SHAREPATH_SL] = join(list[SERVERIP], list[SHARENAME])
        self.share_list.append(list)
        self.share_list_count += 1
        return 1

    def get_tid_from_share(self, share):
        found = 0
        for tidlist in self.share_list:
            if (cmp(tidlist[SHARENAME], share ) == 0):
                found = 1
                break
        if ( found ):
            return tidlist[TID_SL]
        
        return -1

    def list_del_on_tid(self, tid):               
        count = 0    
        for list in self.share_list:
            if list[TID_SL] == fid:
                break
        count+=1
        if count >=1:
            if (count == self.share_list_count) or (count == 1 and self.share_list_count >= 2):
                self.ntc_fid_list = self.share_list[:-1]
                
            elif count == 1 and self.share_list_count > 2:
                self.share_list = self.share_list[0] + self.share_list[count+1:]
                
            else:
                self.share_list = self.share_list[0:count]
                self.share_list = self.share_list[count+1:]
                
            self.share_list_count -= 1        

    def edit_sharepath(self, tid, share):
        count = 0
        found = 0
        for count, list in enumerate(self.share_list):
            if list[TID_SL] == tid:
                found = 1
                break

        join(serverip,share)
        list[SHAREPATH_SL] = join(serverip,share)


##Index of the elements in the fid list 
FILENAME        = 0
FID             = 1
TID             = 2
CREATE_FLAGS    = 3
ACCESS_MASK     = 4
FILE_ATTR       = 5
SHARE_MODE      = 6    
CREATE_OPTIONS  = 7
SECURITY_FLAGS  = 8
DISPOSITION     = 9
IMPERSONATIOM   = 10
EOF             = 11
ALLOC_SIZE      = 12
FILETYPE        = 13
FDNO		= 14

#OPENANX FILE 
SEARCHATTR  = 5
OFILEATTR   = 6
OCRTIME     = 7
OOPENFUNC   = 8
OEOF        = 9
OALLOC      = 10
OFILETYPE   = 11
OSERVFID    = 12
OFDNO	    = 13

class FIDStore:
    def __init__(self):
        self.ntc_fid_list = [['filename', 'fid', 'tid',
                          'create_flags', 'access_mask',
                          'file_attr', 'share_access',
                          'create_options', 'security_flags', 'disposition',
                          'impersonation' , 'eof', 'alloc_size',
                          'filetype', 'fdno'],]
        self.ntc_fid_list_count = 1
        self.open_fid_list = [['filename', 'fid', 'tid',
                          'flags', 'desiredaccess',
                          'searchattr', 'fileattr',
                          'crtime', 'openmode', 'eof', 'alloc_size',
                          'filetype', 'serverfid', 'fdno'],]
        self.open_fid_list_count = 1


    def list_add(self, flist, flag=0):
        if ( flag ):
            if len(flist) != len(self.open_fid_list[0]):
                print 'Error: Length to be added is missing arguments'
                return 0
            self.open_fid_list.append(flist)
            self.open_fid_list_count += 1
            return 1
        
        if len(flist) != len(self.ntc_fid_list[0]):
            print 'Error: Length to be added is missing arguments'
            return 0
        self.ntc_fid_list.append(flist)
        self.ntc_fid_list_count += 1
        return 1
        
    def list_del_on_filename(self, filename, flag=0):
        if filename == None or len(filename) == 0:
            print 'Error: Filename is None or empty'
            return 0
        count = 0
        found = 0
        for fid in (self.ntc_fid_list):
            if ( (cmp(fid[FILENAME], filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                found = 1	
                break
            count += 1
	if found:
 	    self.ntc_fid_list.pop(count)
            self.ntc_fid_list_count -= 1
            return 1

        found = 0    
	count = 0
        for fid in (self.open_fid_list):
            if ( (cmp(fid[FILENAME], filename) == 0) or 
	         (cmp(fid[OFDNO], filename) == 0) ):
		found = 1
                break
            count += 1
        if ( found):
            self.open_fid_list.pop(count)
            self.open_fid_list_count -= 1
            return 1

        return 0        


    def list_del_on_fid(self, fid, flag=0):            
        count = 0
        found = 0
        for fidlist in (self.ntc_fid_list):
            if fidlist[FID] == fid:
                found = 1
                break
            count+=1
        if ( found ):
 	    self.ntc_fid_list.pop(count)
            self.ntc_fid_list_count -= 1
            return 1
		
        found = 0    
	count = 0
        for flist in (self.open_fid_list):
            if (flist[FID]== fid):
                found = 1
                break
            count += 1
        if ( found):
	    self.open_fid_list.pop(count)
            self.open_fid_list_count -= 1
            return 1
        
        return 0

    ## Search file details based on Filename
    def set_fid_on_filename(self, filename, fidno, flag=0):
        if ( flag ==0):
            for fid in self.ntc_fid_list:
                if ( (cmp(fid[FILENAME] ,filename) == 0) or 
		   (cmp(fid[FDNO], filename) == 0) ):
		    if ( fid[FID] == 0):
                        fid[FID] = fidno
                        return 1
        elif ( flag ==1):
            for fid in self.open_fid_list:
                if ((cmp(fid [FILENAME] ,filename) == 0) or
		   (cmp(fid[OFDNO], filename) == 0) ):
		    if ( fid[FID] == 0):
                        fid[FID] = fidno
                        return 1
        return 0

##set_fileinfo_on_filename(self.lastfilename, eof, alloc_size,
##                                                       filetype)
    def set_fileinfo_on_filename(self, filename, eof, alloc_size,
                                 filetype, oplock_level,flag=0):
        if ( flag == 0):
            for fid in self.ntc_fid_list:
                if ((cmp(fid [FILENAME] ,filename) == 0) or
		   (cmp(fid[FDNO], filename) == 0) ):
                    fid[ALLOC_SIZE] = alloc_size
                    fid[EOF] = eof
                    fid[FILETYPE] = filetype
                    fid[CREATE_FLAGS] = oplock_level
                    return 1
        elif (flag==1):
            for fid in self.open_fid_list:
                if ((cmp(fid [FILENAME] ,filename) == 0) or
		   (cmp(fid[OFDNO], filename) == 0) ):
                    fid[OALLOC] = alloc_size
                    fid[OEOF] = eof
                    fid[OFILETYPE] = filetype
                    fid[CREATE_FLAGS] = oplock_level
                    return 1
        return 0


    def get_fileinfo_on_filename(self, filename, flag=0):
        for fid in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return (1, fid[FID],  fid[EOF] , fid[ALLOC_SIZE],
                fid[FILETYPE] )
        for fid in self.open_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[OFDNO], filename) == 0) ):
                return (1, fid[FID],  fid[OEOF] , fid[OALLOC],
                fid[OFILETYPE])
        return 0 , -1, 0, 0, 0
    
    ## Search file details based on Filename
    def get_fid_from_filename(self, filename, flag=0):
	for fid in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [FID]
            
        for fid in self.open_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[OFDNO], filename) == 0) ):
                return 1, fid [FID]
        return 0, -1
    
    def get_tid_from_filename(self, filename, flag=0):
        if (flag==0):
            for fid  in self.ntc_fid_list:
                if ((cmp(fid [FILENAME] ,filename) == 0) or
	            (cmp(fid[FDNO], filename) == 0) ):
                    return 1, fid [TID]
        else:
            for fid  in self.open_fid_list:
                if ((cmp(fid [FILENAME] ,filename) == 0) or
	            (cmp(fid[OFDNO], filename) == 0) ):
                    return 1, fid [TID]
        return 0, -1

    def get_createflags_from_filename(self, filename):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [CREATE_FLAGS]
        return 0, -1    

    def get_access_mask_from_filename(self, filename):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [ACCESS_MASK]
        return 0, -1    

    def get_fileattr_from_filename(self, filename, flag=0):
        for fid in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid[FILE_ATTR]
        return 0, -1    

    def get_sharemode_from_filename(self, filename):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [SHARE_MODE]
        return 0, -1    

    def get_createoptions_from_filename(self, filename):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [CREATE_OPTIONS]
        return 0, -1    

    def get_securityflags_from_filename(self,filename):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, fid [SECURITY_FLAGS]
        return 0, -1

    def get_fileinfolist_from_filename(self, filename, flag=0):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return 1, list
        return 0, []    

    def get_fileinfoargs_from_filename(self, filename, flag=0):
        for fid  in self.ntc_fid_list:
            if ((cmp(fid [FILENAME] ,filename) == 0) or
	        (cmp(fid[FDNO], filename) == 0) ):
                return  1, \
                        fid [FID], \
                        fid [TID], \
                        fid [CREATE_FLAGS], \
                        fid [ACCESS_MASK],  \
                        fid [FILE_ATTR],    \
                        fid [SHARE_MODE],   \
                        fid [CREATE_OPTIONS],\
                        fid [SECURITY_FLAGS]
                        
        return 0, -1, -1, -1, -1, -1 , -1, -1, -1
   
    def get_eof_from_fid(self, fid, flag=0):
	found = 0
        for fidlist in (self.ntc_fid_list):
            if fidlist[FID] == fid:
		found = 1
                return 1, fidlist[EOF]
        for fidlist in (self.open_fid_list):
            if fidlist[FID] == fid:
	        found = 1
                return 1, fidlist[OEOF]
	if found == 0:
            return 0, 0   

    ## Get function to return file details based on FID
    def get_filename_from_fid(self, fid, flag=0):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist [FILENAME]
        return 0, 0

    def set_createflags_from_fid(self, fid, oplocklevel):
	found = 0
        for fidlist in (self.ntc_fid_list):
            if fidlist [FID] == fid:
		found = 1
                fidlist [CREATE_FLAGS] = oplocklevel
		return 1
        for fidlist in (self.open_fid_list):
            if fidlist [FID] == fid:
		found = 1
                fidlist [CREATE_FLAGS] = oplocklevel
		return 1
	if found == 0:
	    return 0
	

    def get_createflags_from_fid(self, fid):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist [CREATE_FLAGS]
        return 0, 0   
 
    def get_access_mask_from_fid(self, fid):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist[ACCESS_MASK]
        return 0, 0

    def get_fileattr_from_fid(self, fid, flag=0):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist [FILE_ATTR]
        return 0, 0   

    def get_shareaccess_from_fid(self, fid):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist [SHARE_MODE]
        return 0, 0  

    def get_createoptions_from_fid(self, fid):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist [CREATE_OPTIONS]
        return 0, 0

    def get_securityflags_from_fid(self, fid):
        for fidlist  in (self.ntc_fid_list):
            if fidlist [FID] == fid:
                return 1, fidlist[SECURITY_FLAGS]
        return 0, 0

    def get_fileinfolist_from_fid(self, fid, flag=0):
        for fidlist in (self.ntc_fid_list):
            if fidlist[FID] == fid:
                return 1, fidlist
        return 0, []    

    def get_fileinfoargs_from_filename(self, fid, flag=0):
        for fidlist in (self.ntc_fid_list):
            if fidlist[FID] == fid:
                return  1, \
                        fidlist[FILENAME], \
                        fidlist[TID], \
                        fidlist[CREATE_FLAGS], \
                        fidlist[ACCESS_MASK], \
                        fidlist[FILE_ATTR], \
                        fidlist[SHARE_MODE], \
                        fidlist[CREATE_OPTIONS], \
                        fidlist[SECURITY_FLAGS]
                        
        return 0, "", -1, -1, -1, -1 , -1, -1, -1 
