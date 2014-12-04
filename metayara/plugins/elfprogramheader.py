from metayara.metatag import _ELF_PROGRAM_HEADER, _ELF_PROGRAMHEADER_TYPE
import struct
import ctypes
from _struct import pack
from metayara import utils

class elfprogramheader():
    """
    >> ELF Field  program header header scan - Only supports 32 Bit applications for now
    """
    
    def __init__(self, handle, ELF_list):
        self.handle = handle
        self.ELF_list = ELF_list
        #self.is_elf(handle)
        self.set_field_header()
        self.elf_programheader()
        
    def set_field_header(self):
        """
        Set header list
        """
        setup = ("Offset", "Type", "Header Field", ",Field", "Integer", "Hexvalue")
        self.ELF_list.append(setup)
    
    def elf_programheader(self):
        """
        Retrieve ELF Program header information from handle
        """
        programheadernumber = utils.get_elf_programheader_number(self.handle)
        endianess = utils.get_endianess(self.handle)
        sectionheader_size = 32
        additional_bytes = int()
        
        for x in range(programheadernumber):
            
            if x> 0:
                """
                Add section header size for next line in section
                """
                additional_bytes+= sectionheader_size
                
            for name, seek, read, pack in _ELF_PROGRAM_HEADER:
                """
                Retrieve ELF Program header
                """
                if name == str('Type;'):
                    clearline = (6 * ("",))
                    self.ELF_list.append(clearline)
                    
                    if additional_bytes > 0:
                        seek+=additional_bytes
                                        
                    byte, realoffset = self.multiple_byte_handler_elf(self.handle, seek , ctypes.sizeof(read))
                    sectionname = struct.unpack(endianess+pack, byte)[0]
                    
                    for item in _ELF_PROGRAMHEADER_TYPE:  
                        if sectionname == item[0]:
                                section = item[1]
                
                    realoffset = hex(realoffset)
                    insert = (realoffset, utils.ctypes_convert(read), section,  str(), str(), str())
                    self.ELF_list.append(insert)
                
                else:
                    if additional_bytes > 0:
                        seek+=additional_bytes
                    byte, realoffset = self.multiple_byte_handler_elf(self.handle, seek , ctypes.sizeof(read))
                    intvalue = struct.unpack(endianess+pack, byte)[0]
                    hexvalue = hex(intvalue)
                    realoffset = hex(realoffset)
                    insert = (realoffset, utils.ctypes_convert(read), str(), name, intvalue, hexvalue)
                    self.ELF_list.append(insert)
                    
                    
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    
    def multiple_byte_handler_elf(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle with entry programheader
        """
        programheaderstart = utils.get_elf_programheader_entry(self.handle)        
        sectionoffset = (programheaderstart+seek)
        handle.seek(sectionoffset, 0)
        byte = handle.read(read)
        return byte, sectionoffset

    
        
        