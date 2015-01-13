from metayara import utils
from metayara.metatag import _ELF_SECTIONHEADER, _ELF_SECTIONHEADER_64, _ELF_SECTION_HEADER_TYPE
import ctypes
import struct
import sys

class elfsection():
    """
    >> ELF String Table Entrys
    """
    def __init__(self, handle, ELF_Section):
        self.handle = handle
        self.ELF_Section = ELF_Section
        self.is_elf(handle)
        self.set_field_header()
        self.elf_section()
        
        
    def is_elf(self, handle):
        check = utils.check_elf(handle)
        if check is False:
            sys.exit("The image does not contain ELF header information")     
        
    def elf_section(self):
        """
        retrieve ELF sectin 
        """
        sectionsize = utils.get_elf_section_entry_size(self.handle)
        sectioncount = utils.get_elf_section_count(self.handle)
        endian = utils.get_endianess(self.handle)
        additional_bytes = int()
        
        version = utils.get_elf_bitversion(self.handle)
        if version == 32:
            ELF_Header = _ELF_SECTIONHEADER
        if version == 64:
            ELF_Header = _ELF_SECTIONHEADER_64
        
        for x in range(sectioncount):
            insert = []
            if x> 0:
                additional_bytes+= sectionsize
            
            for name, seek, read, pack in ELF_Header:   
                byte, realoffset = self.byte_handler(self.handle, (seek+additional_bytes), ctypes.sizeof(read))
                integer = struct.unpack((endian+ pack), byte)[0]
                hexvalue = hex(integer)
                
                if name == 'Type;':
                    for item in _ELF_SECTION_HEADER_TYPE:  
                        if hex(item[1]) == hexvalue:
                            insert.append(item[0])
                            
                else:
                
                    insert.append(hexvalue)
                
            
            self.ELF_Section.append(insert)

    def set_field_header(self):
        """
        Set field header
        """
        version = utils.get_elf_bitversion(self.handle)
        if version == 32:
            setup = ("Name", "Type", "Flags", "Virtual Address", "Offset", "Size", "Link", "Info", "Addralign", "Entsize")
            self.ELF_Section.append(setup)    
        if version == 64:
            setup = ("Name", "Type", "Flags", "Virtual Address", "Offset", "Size", "Link", "Info", "Addralign", "Entsize")
            self.ELF_Section.append(setup)    
        
    def byte_handler(self, handle, seek, read):
        """
        retrieve offset and byte from elf handle
        """
        sectionentry = utils.get_elf_section_entry(handle)
        handle.seek(seek+sectionentry, 0)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
        