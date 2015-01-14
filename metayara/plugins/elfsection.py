from metayara import utils
from metayara.metatag import _ELF_SECTIONHEADER, _ELF_SECTIONHEADER_64, _ELF_SECTION_HEADER_TYPE, _ELF_SECTION_FLAGS
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
            
    def set_char_flags(self, flag, flag_list):
        """
        Returns Flags from search list
        """
        local_tbl = []
        local_string = str()
        name, intvalue = flag
        binary_value = ('{:05b}'.format(intvalue))
        
        counter = 0
        for flag in reversed(binary_value):
            flag = int(flag)
            
            if flag == True:
                
                flag_name, flag_description = flag_list[counter]
                flag_name = flag_name
                flag_description = flag_description
                flag_set = "TRUE"
           
                local_string+=flag_description
                 
             
            counter+=1
            
        if counter == 5:
            return local_string
    
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
                
                if name == 'Name;':
                    shtr_tbl_entry = self.elf_stringtable()
                    shtr_offset = integer
                    self.handle.seek(shtr_tbl_entry+shtr_offset, 0)
                    
                    str_name = str()
                    while True:
                        data = self.handle.read(1)
                        data = struct.unpack((endian + "B"), data)[0]
                        
                        if data == 0:
                            insert.append(str_name)
                            break
                        else:
                            str_name+=chr(data)
                
                elif name == 'Type;':
                    for item in _ELF_SECTION_HEADER_TYPE:  
                        if hex(item[1]) == hexvalue:
                            insert.append(item[0])
                
                elif name == 'Flags;':
                    set_elfsec_flag = (name, integer)
                    flag = self.set_char_flags(set_elfsec_flag, _ELF_SECTION_FLAGS)
                    insert.append(flag)
                    
                else:
                    
                    insert.append(hexvalue)
                
            self.ELF_Section.append(insert)

    def set_field_header(self):
        """
        Set field header
        """
        version = utils.get_elf_bitversion(self.handle)
        if version == 32:
            print("W (write), A (alloc), X (execute), M (merge), S (strings)")
            setup = ("Name", "Type", "Flags", "Virtual Address", "Offset", "Size", "Link", "Info", "Addralign", "Entsize")
            self.ELF_Section.append(setup)    
        if version == 64:
            print("W (write), A (alloc), X (execute), M (merge), S (strings)")
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

    def elf_stringtable(self):
        sectionsize = utils.get_elf_section_entry_size(self.handle)        
        shtrtable_index = utils.get_elf_shtrtable_index(self.handle)
        sectioncount = utils.get_elf_section_count(self.handle)
        endian = utils.get_endianess(self.handle)
        additional_bytes = int()
            
        byte, realoffset = self.byte_handler(self.handle, (sectionsize*shtrtable_index)+16, 4)
        offset_stringtable = struct.unpack((endian+ "L"), byte)[0]
        return offset_stringtable
        
        
        
        