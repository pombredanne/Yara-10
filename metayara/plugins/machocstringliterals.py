from metayara import utils
import ctypes
import struct
import re

class machocstringliterals():
    """
    > MachO Cstring literals
    """
    def __init__(self, handle, MachO_Cstring_list):
        self.handle = handle
        self.MachO_Cstring_list = MachO_Cstring_list
        self.set_field_header()
        self.get_MachO_CstringOffset(handle)
        
    #CSTRING LITERAL -> SECTION64-> _cstring
    
    
    def set_field_header(self):
        setup = ("CstringSize", "CstringIndex")
        
        self.MachO_Cstring_list.append(setup)
        
        
        
    def get_MachO_CstringOffset(self, handle):
        loadcommands = utils.get_macho_loadcommands_64(handle)
        start_offset = 32
        start_offset_cmdsize = 32
        for x in range(loadcommands):
            
            handle.seek(start_offset, 0)
            cmd = handle.read(4)
            cmd = struct.unpack("<L", cmd)[0]
        
            handle.seek(start_offset+4, 0)
            cmdsize = handle.read(4)
            cmdsize = struct.unpack("<L", cmdsize)[0]
            
            if hex(cmd) == '0x19':
                handle.seek(start_offset+8, 0)
                
                data = handle.read(16)
                section = str()
                
                for item in data:
                    if item != 0:
                        section+=chr(item)
                     
                sectiontext = "__TEXT"
                
                if section in sectiontext:
                    handle.seek(start_offset+64)
                    
                    SectionNumber = handle.read(4)
                    SectionNumber = struct.unpack("<L", SectionNumber)[0]
                    
                    SectionSize = 80
                    for x in range(SectionNumber):
                        handle.seek(start_offset+72)
                        data = handle.read(16)
                        section = str()
                
                        for item in data:
                            if item != 0:
                                section+=chr(item)
                                
                        
                        if section == '__cstring':
                            handle.seek(start_offset+112)
                            cStringTblSize = handle.read(8)
                            cStringTblSize = struct.unpack("<Q", cStringTblSize)[0]
                            
                            handle.seek(start_offset+120)
                            cStringTblOffset = handle.read(4)
                            cStringTblOffset = struct.unpack("<L", cStringTblOffset)[0]
                            
                            localcounter = 0
                            value = str()
                            for x in range(cStringTblSize):
                                
                                handle.seek(cStringTblOffset+localcounter, 0)
                                data = handle.read(1)
                                if data == b'\x00':
                                    optionalfield = value
                                    insert = (len(optionalfield), optionalfield)
                                    self.MachO_Cstring_list.append(insert)
                                    value = str()
                                else:
                                    if len(value) > 64:
                                        insert = (len(value), value)
                                        self.MachO_Cstring_list.append(insert)
                                        value = str()
                                    for item in data:
                                        data = chr(item)
                                        data = data.lstrip()
                                        data = data.rstrip()
                                        value+=data
                                    
                                        
                                        
                                    
                                localcounter+=1
                        
                        start_offset+=SectionSize
                        
                        
            start_offset+=cmdsize