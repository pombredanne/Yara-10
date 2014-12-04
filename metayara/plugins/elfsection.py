from metayara import utils
from metayara.metatag import _ELF_SECTIONHEADER
import ctypes
import struct

class elfsection():
    """
    >> Elf String Table Entrys
    """
    def __init__(self, handle, ELF_Section):
        self.handle = handle
        self.ELF_Section = ELF_Section
        self.set_field_header()
        self.elf_section()
        
        
    def elf_section(self):
        
        
        sectionsize = utils.get_elf_section_entry_size(self.handle)
        sectioncount = utils.get_elf_section_count(self.handle)
        additional_bytes = int()
        
        for x in range(sectioncount):
            insert = []
            if x> 0:
                additional_bytes+= sectionsize
            
            for name, seek, read, pack in _ELF_SECTIONHEADER:
                byte, realoffset = self.byte_handler(self.handle, (seek+additional_bytes), ctypes.sizeof(read))
                integer = struct.unpack(pack, byte)[0]
                hexvalue = hex(integer)
                insert.append(hexvalue)
            
            self.ELF_Section.append(insert)
        
            
    def set_field_header(self):
        setup = ("Name", "Type", "Flags", "Virtual Address", "Offset", "Size", "Link", "Info", "Addralign", "Entsize")
        self.ELF_Section.append(setup)    
        
    def byte_handler(self, handle, seek, read):
        sectionentry = utils.get_elf_section_entry(handle)
        handle.seek(seek+sectionentry, 0)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
        