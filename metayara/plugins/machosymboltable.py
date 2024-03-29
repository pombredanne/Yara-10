from metayara import utils
import struct
import ctypes
import sys
from metayara.metatag import _MACHO_SYMTAB_STRUCT
from metayara.metatag import _MACHO_DESCPITION_FLAGS


class machosymboltable():
    """
    >> Macho Symbol Table
    """
    
    def __init__(self, handle, MachO_SymTable_List):
        self.handle = handle
        self.MachO_SymTable_List = MachO_SymTable_List
        self.is_MachO(handle)
        self.set_field_header()
        self.MachO_SymbolTable(handle)
     
    def is_MachO(self, handle):
        check = utils.check_macho_version(handle, True)
        
        if check is False:
            sys.exit("The image does not contain MachO header information") 
                
    def set_field_header(self):
        """
        Set header list
        """
        setup = ("Offset", "Type", "Field", "Integer", "Hexadecimal" ,"OptionalFields")
        self.MachO_SymTable_List.append(setup)
    
    def get_string(self, handle, name, intvalue, StrtblOffset):
        if name == 'StringTableIndex;':
            if intvalue == 0:
                optionalfield = "Emtpy String"
                return optionalfield
            else:
                        
                localcounter = 0
                value = str()
                while True:
                    handle.seek(StrtblOffset+intvalue+localcounter)
                    data = handle.read(1)
                    if data == b'\x00':
                        optionalfield = value
                        return value
                        break
                    else:
                        data = data.decode('UTF-8')
                        value+=data
                        localcounter+=1
        else:
            optional = '.'
            return optional
        
   
     
    def MachO_SymbolTable(self, handle):
        SymtblOffset, SymtblNmbr, StrtblOffset, StrtblNmbr = self.get_MachO_TableOffsets(handle)
        
        for x in range(SymtblNmbr):
            for name, seek, read, pack in _MACHO_SYMTAB_STRUCT:
            
                byte, realoffset = self.byte_handler(handle, (seek+SymtblOffset), ctypes.sizeof(read))
                intvalue = struct.unpack("<" + pack, byte)[0]
                hexvalue = hex(intvalue)
                realoffset = hex(realoffset)
                set_optional_field = '.'
                if name == 'StringTableIndex;':
                    set_optional_field = self.get_string(handle, name, intvalue, StrtblOffset)
                    
                if name == "Description;":
                    set_char_flag = (name, intvalue)
                    self.set_char_flags(set_char_flag, _MACHO_DESCPITION_FLAGS)
                
                    
                insert = (realoffset, utils.ctypes_convert(read), name, intvalue, hexvalue, set_optional_field)          
                self.MachO_SymTable_List.append(insert) 
                    
            clearline = (7 * ("",))
            self.MachO_SymTable_List.append(clearline)
            
            SymtblOffset+=16 #Size of SymbolTable Entries
    
    
                            
        optional = '.'
        return optional     
    
    def set_char_flags(self, flag, flag_list):
        """
        Returns Flags from search list
        """
        clearline = (6 * ("",))
        
        name, intvalue = flag
        binary_value = ('{:010b}'.format(intvalue))
            
        counter = 0
        for flag in reversed(binary_value):
            flag = int(flag)
                
            if flag == True:
                    
                flag_name, flag_description = flag_list[counter]
                flag_name = flag_name
                flag_description = flag_description
                flag_set = "TRUE"
            
                
                insert = (" ", " ", "FLAG", flag_name, flag_set, flag_description)
                
                self.MachO_SymTable_List.append(insert)
                counter+=1
        
            
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    
        
    def get_MachO_TableOffsets(self, handle):
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
            
            if hex(cmd) == '0x2':
                """
                Check if symbtbl
                """
                handle.seek(start_offset+8, 0)
                SymtblOffset = handle.read(4)
                SymtblOffset = struct.unpack("<L", SymtblOffset)[0]
                
                handle.seek(start_offset+12, 0)
                SymtblNumber = handle.read(4)
                SymtblNumber = struct.unpack("<L", SymtblNumber)[0]
                
                handle.seek(start_offset+16, 0)
                StringTbleOffset = handle.read(4)
                StringTbleOffset = struct.unpack("<L", StringTbleOffset)[0]
                
                handle.seek(start_offset+20, 0)
                StringTbleNumber = handle.read(4)
                StringTbleNumber = struct.unpack("<L", StringTbleNumber)[0]
                return SymtblOffset, SymtblNumber, StringTbleOffset, StringTbleNumber
                        
            start_offset+=cmdsize