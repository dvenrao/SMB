from .. import smb2
from .. import constants
import string

class SMBQuery_directory_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x21'),
        ('FileInformationClass','<B=0x0'),
        ('Flags','<B=0x0'),
        ('FileIndex','<I=0x0'),
        ('FileId','<16s=""'),
        ('FileNameOffset','<H=0x0'),
        ('FileNameLength','<H=0x0'),
        ('OutputBufferLength','<I=0x0'),
    )
class SMBQuery_directory_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBQuery_directoryResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('OutputBufferOffset ','<H'),
        ('OutputBufferLength ','<I'),
        ('Buffer',':'),
    )
class SMBQuery_directoryResponse_Data_FileDirectoryInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('EndOfFile','<Q'),
        ('AllocationSize','<Q'),
        ('FileAttributes','<I'),
        ('FileNameLength','<I'),
        ('FileName',':'),
    )
class SMBQuery_directoryResponse_Data_FileFullDirectoryInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('EndOfFile','<Q'),
        ('AllocationSize','<Q'),
        ('FileAttributes','<I'),
        ('FileNameLength','<I'),
        ('EaSize','<I'),
        ('FileName',':'),
    )
class SMBQuery_directoryResponse_Data_FileIdFullDirectoryInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('EndOfFile','<Q'),
        ('AllocationSize','<Q'),
        ('FileAttributes','<I'),
        ('FileNameLength','<I'),
        ('EaSize','<I'),
        ('Reserved','<I'),
        ('FileId','<Q'),
        ('FileName',':'),
    )
class SMBQuery_directoryResponse_Data_FileBothDirectoryInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('EndOfFile','<Q'),
        ('AllocationSize','<Q'),
        ('FileAttributes','<I'),
        ('FileNameLength','<I'),
        ('EaSize','<I'),
        ('ShortNameLength','<B'),
        ('Reserved','<B'),
        ('ShortName','<24s=""'),
        ('FileName',':'),
    )
class SMBQuery_directoryResponse_Data_FileIdBothDirectoryInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('EndOfFile','<Q'),
        ('AllocationSize','<Q'),
        ('FileAttributes','<I'),
        ('FileNameLength','<I'),
        ('EaSize','<I'),
        ('ShortNameLength','<B'),
        ('Reserved1','<B'),
        ('ShortName','<24s=""'),
        ('Reserved2','<H'),
        ('FileId','<Q'),
        ('FileName',':'),
    )

class SMBQuery_directoryResponse_Data_FileNamesInformation(smb2.Structure):
    structure = (
        ('NextEntryOffset','<I'),
        ('FileIndex','<I'),
        ('FileNameLength','<I'),
        ('FileName',':'),
    )

def query_directory_Extend_Request_Structure(Query_directory,fileInfo,flag,fileIndex,fileId,pattern):
        Smb2Constants = constants.smb2Constants()
        
        Query_directory['Parameters'] = SMBQuery_directory_Parameters()
        Query_directory['Data'] = SMBQuery_directory_Data()

        Query_directory['Parameters']['FileInformationClass']   = fileInfo
        Query_directory['Parameters']['Flags']                  = flag    
        Query_directory['Parameters']['FileIndex']              = fileIndex
        Query_directory['Parameters']['FileId']                 = fileId                 
        Query_directory['Parameters']['FileNameOffset']         = 64 + len(Query_directory['Parameters'])
        pattern = pattern.encode('utf-16-le')
        Query_directory['Parameters']['FileNameLength']         = len(pattern)  
        Query_directory['Parameters']['OutputBufferLength']     = 65536
                                                                         
        Query_directory['Data']['data'] = pattern
        return Query_directory,fileInfo

def query_directory_Response_Structure(query_directoryResponse,fileInfo):
        Smb2Constants = constants.smb2Constants()
        query_directoryParameters = SMBQuery_directoryResponse_Parameters(query_directoryResponse['Parameters'])
        data = query_directoryParameters['Buffer']
        #length = query_directoryParameters['OutputBufferLength']
        
        NextEntryOffset = 0
        listResponse = []
        cnt = 0
        
        if fileInfo == 1:
           while True:
              data = data[NextEntryOffset:]
              FileDirectoryInformation = SMBQuery_directoryResponse_Data_FileDirectoryInformation(data)
              NextEntryOffset = FileDirectoryInformation['NextEntryOffset']
              FileIndex       = FileDirectoryInformation['FileIndex']
              CreationTime    = FileDirectoryInformation['CreationTime']
              LastAccessTime  = FileDirectoryInformation['LastAccessTime']
              LastWriteTime   = FileDirectoryInformation['LastWriteTime']
              ChangeTime      = FileDirectoryInformation['ChangeTime']
              EndOfFile = FileDirectoryInformation['EndOfFile']
              AllocationSize = FileDirectoryInformation['AllocationSize']
              FileAttributes = FileDirectoryInformation['FileAttributes']
              FileNameLength = FileDirectoryInformation['FileNameLength']
              FileName = FileDirectoryInformation['FileName']
              FileName = FileName[:FileNameLength]
              li = [FileName,CreationTime,LastAccessTime,LastWriteTime,ChangeTime,\
                           EndOfFile,AllocationSize,FileAttributes]
              listResponse.append(li)
              cnt += 1
              if NextEntryOffset == 0:
                 break
        elif fileInfo == 2:
           while True:
              data = data[NextEntryOffset:]
              FileFullDirectoryInformation = SMBQuery_directoryResponse_Data_FileFullDirectoryInformation(data)
              NextEntryOffset = FileFullDirectoryInformation['NextEntryOffset']
              if NextEntryOffset == 0:
                 break
        elif fileInfo == 38:
           while True:
              data = data[NextEntryOffset:]
              FileIdFullDirectoryInformation = SMBQuery_directoryResponse_Data_FileIdFullDirectoryInformation(data)
              NextEntryOffset = FileIdFullDirectoryInformation['NextEntryOffset']
              if NextEntryOffset == 0:
                 break
        elif fileInfo == 3:
           while True:
              data = data[NextEntryOffset:]
              FileBothDirectoryInformation = SMBQuery_directoryResponse_Data_FileBothDirectoryInformation(data)
              NextEntryOffset = FileBothDirectoryInformation['NextEntryOffset']
              if NextEntryOffset == 0:
                 break
        elif fileInfo == 37:
           while True:
              data = data[NextEntryOffset:]
              FileIdBothDirectoryInformation = SMBQuery_directoryResponse_Data_FileIdBothDirectoryInformation(data)
              NextEntryOffset = FileIdBothDirectoryInformation['NextEntryOffset']
              if NextEntryOffset == 0:
                 break
        elif fileInfo == 12:
           while True:
              data = data[NextEntryOffset:]
              FileNamesInformation = SMBQuery_directoryResponse_Data_FileNamesInformation(data)
              NextEntryOffset = FileNamesInformation['NextEntryOffset']
              FileNameLength = FileNamesInformation['FileNameLength']
              FileName = FileNamesInformation['FileName'][:FileNameLength]
              FileName = FileName.decode('utf-16-le')
              print FileName
              if NextEntryOffset == 0:
                 break

        #print listResponse
        return listResponse,cnt
        

def query_directory_Request_Structure(Query_directory, fileId, *query_directory_params):
        fileinfofound = 0
        flagfound = 0
        fileindexfound = 0
        fileidfound = 0
        patternfound = 0
        
        cnt = 0
        while ( cnt < len(query_directory_params)):
            tmpstr = query_directory_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'fileinfo') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                fileinfo = eval(tmpstr)
                fileinfofound = 1
            elif( string.find(tmpstr, 'flag') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                flag = tmpstr
                flagfound = 1
            elif( string.find(tmpstr, 'fileindex') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                fileindex = tmpstr
                fileindexfound = 1
            elif( string.find(tmpstr, 'fileid') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                fileid = tmpstr
                fileidfound = 1
            elif( string.find(tmpstr, 'pattern') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                pattern = tmpstr
                patternfound = 1
            cnt += 1

        if (fileinfofound == 0):
            fileinfo = 0x01
        if (flagfound == 0):
            flag = 0x0
        if (fileindexfound == 0):
            fileindex = 0x0
        if (fileidfound == 0):
            fileid = 0x0
        if (patternfound == 0):
            pattern = '*'

        Query_directory1 = query_directory_Extend_Request_Structure(Query_directory,\
                                  fileinfo,flag,fileindex,fileId,pattern)
        return Query_directory1