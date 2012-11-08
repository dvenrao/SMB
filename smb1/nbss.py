#!/usr/bin/env python

import os, string, struct
import pdb

class NBT:
    @staticmethod    
    def verifyNBT(data):
        type, flags, length = struct.unpack('>cBH', data[:4])
        flags = flags << 16
        length = flags | length
        header, smbdata = data[:4], data[4:]
        #print 'Length in NBT header = %d'%length
        #print 'SMBlen = %d'%len(smbdata)
        if (string.find(smbdata, "SMB") < 0):
            return 0, 1, len(data), data

        elif ( len(smbdata) > length):
            return 1, 0, len(smbdata), smbdata
            
        return 1, 0, len(smbdata), smbdata

    
    @staticmethod
    def construct_nbt_request(data, flags=0x00 , sess_msg=0x00):
        request = struct.pack('>BBH', sess_msg, flags, len(data)) 
        return request


    
                        
            
                                     
 
