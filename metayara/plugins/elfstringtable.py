from metayara import utils
import struct
from metayara.metatag import _ELF_SECTIONHEADER
import ctypes

class elfstringtable():
    """
    >> ELF String Table Entrys
    """
    def __init__(self, handle, ELF_stringtable):
        self.handle = handle
        self.ELF_stringtable = ELF_stringtable
        self.set_field_header()
        self.elf_stringtable()
        
    def set_field_header(self):
        """
        Set Field header
        """
        setup = ("Size of String", "Name")
        self.ELF_stringtable.append(setup)
        
            
    def elf_stringtable(self):
        sectionsize = utils.get_elf_section_entry_size(self.handle)
        sectioncount = utils.get_elf_section_count(self.handle)
        endian = utils.get_endianess(self.handle)
        additional_bytes = int()
        
        
        for x in range(sectioncount):
            
            if x > 0:
                additional_bytes+=sectionsize
                
                for name, seek, read, pack in _ELF_SECTIONHEADER:   
                    byte, realoffset = self.byte_handler(self.handle, (seek+additional_bytes), ctypes.sizeof(read))
                    integer = struct.unpack((endian+ pack), byte)[0]
                
                    if name == 'Type;':
                        if integer == 3:
                            byte, realoffset =self.byte_handler(self.handle, seek+additional_bytes+12, ctypes.sizeof(read))
                            offset_stringtable = struct.unpack((endian+ pack), byte)[0]
                            
                            byte, realoffset =self.byte_handler(self.handle, seek+additional_bytes+16, ctypes.sizeof(read))
                            offset_stringtable_size = struct.unpack((endian+ pack), byte)[0]
                            
                            self.handle.seek(offset_stringtable, 0)
                            data = self.handle.read(offset_stringtable_size)
            
                            entry = str()
            
                            for item in data:
                                if item == 0:
                                    insert = (len(entry), entry)
                                    self.ELF_stringtable.append(insert)
                                    entry = str()
                                else:
                                    entry+=chr(item)
                        
                
    def byte_handler(self, handle, seek, read):
        """
        retrieve offset and byte from elf handle
        """
        sectionentry = utils.get_elf_section_entry(handle)
        handle.seek(seek+sectionentry, 0)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset        
        

        