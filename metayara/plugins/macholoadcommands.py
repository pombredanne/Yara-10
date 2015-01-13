from metayara import utils
from metayara.metatag import _MACHO_LC_SEGMENT_64
from metayara.metatag import _MACHO_LC_DYLD_INFO_ONLY
from metayara.metatag import _MACHO_LC_SYMTAB
from metayara.metatag import _MACHO_LOADCOMMAND_TYPE
from metayara.metatag import _MACHO_LC_DYSYMTAB
from metayara.metatag import _MACHO_LC_VERSION_MIN_MACOSX
from metayara.metatag import _MACHO_LC_MAIN
from metayara.metatag import _MACHO_LC_LOAD_DYLIB
from metayara.metatag import _MACHO_LC_LINKEDIT_DATA_COMMAND


import struct
import ctypes
import sys


class macholoadcommands():
    """
    >> MachO Header Loader Commands
    """
    
    def __init__(self, handle, MachO_List):
        self.handle = handle
        self.MachO_List = MachO_List  
        self.is_MachO(handle)
        self.set_field_header()  
        self.MachO_LoadCommands(handle)
        
    def is_MachO(self, handle):
        check = utils.check_macho_version(handle, True)
        
        if check is False:
            sys.exit("The image does not contain MachO header information")     
        
    def set_field_header(self):
        """
        Set header list
        """
        setup = ("Offset", "Type", "FieldHeader", "Field", "Integer", "Hexadecimal" ,"OptionalFields")
        self.MachO_List.append(setup) 
        
        
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in _MACHO_LOADCOMMAND_TYPE:
            
            if field in item[0]:

                if hexvalue == hex(item[1]):
                    return item[2]
                            
        optional = '.'
        return optional

    def MachO_LoadCommands(self, handle):
        loadcommands = utils.get_macho_loadcommands_64(handle)
        start_offset = 32
        
        for x in range(loadcommands):
            handle.seek(start_offset, 0)
            cmd = handle.read(4)
            cmd = struct.unpack("<L", cmd)[0]
            command = 'Command'
            set_optional_field = self.check_tags(command, hex(cmd))
            insert = (hex(start_offset), utils.ctypes_convert(ctypes.c_uint32), command, cmd, hex(cmd), set_optional_field)  
                    
            self.MachO_List.append(insert) 
            cmd = hex(cmd)
            
            handle.seek(start_offset+4, 0)
            cmdsize = handle.read(4)
            cmdsize = struct.unpack("<L", cmdsize)[0]
            
            insert = (hex(start_offset+4), utils.ctypes_convert(ctypes.c_uint32), 'CommandSize', cmdsize, hex(cmdsize), ".")          
            self.MachO_List.append(insert) 
            
                 
            if cmd == '0x19':
                
                handle.seek(start_offset+8, 0)
                data = handle.read(16)
                data = data.decode('UTF-8')
                insert = (hex(start_offset+8), utils.ctypes_convert((ctypes.c_byte) * 16), data, "", "", ".")
                self.MachO_List.append(insert) 
                
                for name, seek, read, pack in _MACHO_LC_SEGMENT_64:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (7 * ("",))
                self.MachO_List.append(clearline)
            
            elif cmd == '0x80000022':
                
                for name, seek, read, pack in _MACHO_LC_DYLD_INFO_ONLY:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)
                
            elif cmd == '0x2':
                
                for name, seek, read, pack in _MACHO_LC_SYMTAB:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)
                
            elif cmd == '0xb':
                
                for name, seek, read, pack in _MACHO_LC_DYSYMTAB:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)                
                
            elif cmd == '0xe':
                
                handle.seek(start_offset+8)
                data = handle.read(4)
                data = struct.unpack("<L", data)[0] 
                insert = (realoffset, utils.ctypes_convert(ctypes.c_uint32), "StringOffset", data, hex(data), ".")          
                self.MachO_List.append(insert) 
                
                handle.seek(start_offset+12)
                data = handle.read(cmdsize-12)
                data = data.decode('UTF-8')
                insert = (realoffset, utils.ctypes_convert(ctypes.c_byte * (cmdsize-12)), "Name", "", data, ".")          
                self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)          
                
            elif cmd == '0x1b':
                handle.seek(start_offset+8)
                data = handle.read(cmdsize-8)
                data = struct.unpack(">LLLL", data)
                
                c = str()
                for item in data:
                    
                    c+=hex(item)
                    
                uuid = str()
                uuid+=c[2:10]
                uuid+='-'
                uuid+=c[12:16]
                uuid+='-'
                uuid+=c[16:20]
                uuid+='-'
                uuid+=c[22:26]
                uuid+='-'
                uuid+=c[26:]
                
                insert = (realoffset, utils.ctypes_convert(ctypes.c_uint32 * 4), "UUID", "", "", uuid.upper())          
                self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)   
                
            elif cmd == '0x24':
                for name, seek, read, pack in _MACHO_LC_VERSION_MIN_MACOSX:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)                
                       
            elif cmd == '0x2a':
            
                handle.seek(start_offset+8)         
                data = handle.read(ctypes.sizeof(ctypes.c_uint64))
                data = struct.unpack("<Q", data)[0]
                insert = (realoffset, utils.ctypes_convert(ctypes.c_uint32), "Version", data, hex(data), ".")          
                self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline) 
                       
            elif cmd == '0x80000028':
                for name, seek, read, pack in _MACHO_LC_MAIN:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)                
                       
                       
            elif cmd == '0xc':
                for name, seek, read, pack in _MACHO_LC_LOAD_DYLIB:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                      
                
                handle.seek(start_offset+24)
                data = handle.read(cmdsize-24)      
                data = data.decode('UTF-8')
                insert = (realoffset, utils.ctypes_convert(ctypes.c_byte * (cmdsize-24)), "Name", "", data, ".")          
                self.MachO_List.append(insert) 
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)    
                
            elif cmd == '0x26':
                for name, seek, read, pack in _MACHO_LC_LINKEDIT_DATA_COMMAND:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                
                clearline = (6 * ("",))
                self.MachO_List.append(clearline) 
                
            elif cmd == '0x29':
                for name, seek, read, pack in _MACHO_LC_LINKEDIT_DATA_COMMAND:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                
                clearline = (6 * ("",))
                self.MachO_List.append(clearline)
                
            elif cmd == '0x2b':
                for name, seek, read, pack in _MACHO_LC_LINKEDIT_DATA_COMMAND:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                
                clearline = (6 * ("",))
                self.MachO_List.append(clearline) 
        
        
            elif cmd == '0x1d':
                for name, seek, read, pack in _MACHO_LC_LINKEDIT_DATA_COMMAND:
                    byte, realoffset = self.byte_handler(handle, (seek+ start_offset), ctypes.sizeof(read))
                    integer = struct.unpack("<" + pack, byte)[0]
                    hexvalue = hex(integer)
                    realoffset = hex(realoffset)
            
                    insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, ".")          
                    self.MachO_List.append(insert) 
                
                clearline = (6 * ("",))
                self.MachO_List.append(clearline) 
                   
            start_offset+=cmdsize
                            
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    