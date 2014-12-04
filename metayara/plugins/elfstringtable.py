from metayara import utils
import struct

class elfstringtable():
    """
    >> Elf String Table Entrys
    """
    def __init__(self, handle, ELF_stringtable):
        self.handle = handle
        self.ELF_stringtable = ELF_stringtable
        self.set_field_header()
        self.elf_stringtable()
        
    def set_field_header(self):
        setup = ("Size of String", "Name")
        self.ELF_stringtable.append(setup)
        
            
    def elf_stringtable(self):
        entry = utils.get_elf_section_entry(self.handle)
        entry_size = utils.get_elf_section_entry_size(self.handle)
        shtrtable_index = utils.get_elf_shtrtable_index(self.handle)
        endian = utils.get_endianess(self.handle)
        
        self.handle.seek(entry + (entry_size * shtrtable_index) + 16 )
        data = self.handle.read(4)
        strintable_entry = struct.unpack((endian + "L"), data)[0]
        
        self.handle.seek(entry + (entry_size * shtrtable_index) + 16 + 4 )
        data = self.handle.read(4)
        strintable_entry_size = struct.unpack((endian + "L"), data)[0]
       
        self.handle.seek(strintable_entry, 0)
        data = self.handle.read(strintable_entry_size)

        entry = str()
        
        for item in data:
            if item == 0:
                insert = (len(entry), entry)
                self.ELF_stringtable.append(insert)
                entry = str()
            else:
                entry+=chr(item)
        
        
        