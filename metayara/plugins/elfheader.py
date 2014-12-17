from metayara.metatag import _ELF_SECTION_HEADER, _SECTION_HEADER_INFO
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
        self.elf_file(handle)
        
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in _SECTION_HEADER_INFO:
            if field is item[0]:
                if hexvalue == hex(item[1]):
                    return item[2]        
                
        optionalempty = '.'
        return optionalempty
        
    def set_field_header(self):
        """
        Set Field header
        """
        setup = ("Offset", "Bit Type", "Field", "Integer", "Hex", "Optional Field")
        self.ELF_list.append(setup) 
        
    def elf_file(self, handle):
        """
        Retrieve endian
        """
        endian = utils.get_endianess(handle)
        """
        Check bit version
        """
        version = utils.get_elf_bitversion(handle)
        additonalbyte = 0
        for name, seek ,read, pack in _ELF_SECTION_HEADER:
            if version == 64:
                if name in ("Entry Point", "Entry Program Headers", "Entry Section Header"):
                    if name == 'Entry Point':
                        read=ctypes.c_uint64
                        pack+="L"
                    if name == "Entry Program Headers":
                        seek+=4
                        read=ctypes.c_uint64
                        pack+="L"
                    if name == "Entry Section Header":
                        seek+=8
                        read=ctypes.c_uint64
                        pack+="L"
                        additonalbyte = 12
                        
            byte, realoffset = self.byte_handler(handle, additonalbyte+seek, ctypes.sizeof(read))
            integer = struct.unpack((endian+pack), byte)[0]
            hexvalue = hex(integer)
            realoffset = hex(realoffset)
            set_optional_field = self.check_tags(name, hexvalue)
            insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, set_optional_field)
            self.ELF_list.append(insert)
            
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
