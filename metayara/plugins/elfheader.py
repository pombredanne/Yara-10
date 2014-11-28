from metayara.metatag import _SECTION_HEADER, _SECTION_HEADER_INFO
import ctypes
from metayara import utils
import struct

class elfheader():
    """
    >> ELF Field header scan - Only supports 32 Bit applications for now
    """
    
    
    def __init__(self, handle, ELF_list):
        self.handle = handle
        self.ELF_list = ELF_list
        #self.is_elf(handle)
        self.set_field_header()
        self.elffile(handle)
        
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in _SECTION_HEADER_INFO:
            if field is item[0]:
                if hexvalue == hex(item[1]):
                    return item[2]        
                
        optional = '.'
        return optional
        
    def set_field_header(self):
        setup = ("Offset", "Bit Type", "Field", "Integer", "Hex", "Optional Field")
        self.ELF_list.append(setup) 
        
    def elffile(self, handle):
        endian = self.get_endianess(handle)
        for name, seek ,read, pack in _SECTION_HEADER:
            
            byte, realoffset = self.byte_handler(handle, seek, ctypes.sizeof(read))
            integer = struct.unpack((endian+pack), byte)[0]
            hexvalue = hex(integer)
            realoffset = hex(realoffset)
            set_optional_field = self.check_tags(name, hexvalue)
            insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, set_optional_field)
            self.ELF_list.append(insert)
            
    def byte_handler(self, handle, seek, read):
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    
    def get_endianess(self, handle):
        handle.seek(5, 0)
        data = handle.read(1)
        data = struct.unpack("B", data)[0]
        
        if data == 1:
            return '<'
        elif data == 2:
            return '>'
        