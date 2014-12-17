from metayara.metatag import _MACHO_HEADER_64, _MACHO_HEADER_64_INFO, _MACHO_FLAGS
from metayara import utils
import ctypes
import struct
import re


class machoheader():
    """
    >> MachO file header
    """
    def __init__(self, handle, MachO_List):
        self.handle = handle
        self.MachO_List = MachO_List
        self.set_field_header()
        self.macho_file_header()
        
        
    def set_field_header(self):
        """
        Set header list
        """
        setup = ("Offset", "Type", "Field", "Integer", "Hexadecimal" ,"OptionalFields")
        self.MachO_List.append(setup)
        
    def macho_file_header(self):
        """
        Retrieve Dos information from handle
        """
        for name, seek, read, pack in _MACHO_HEADER_64:
            byte, realoffset = self.byte_handler(self.handle, seek, ctypes.sizeof(read))
            integer = struct.unpack("<" + pack, byte)[0]
            hexvalue = hex(integer)
            realoffset = hex(realoffset)
            set_optional_field = self.check_tags(name, hexvalue)
            insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, set_optional_field)
             
            self.MachO_List.append(insert) 
            
            if name == "Flags;":
                set_char_flag = (name, integer)
                self.set_char_flags(set_char_flag, _MACHO_FLAGS)
                
    def set_char_flags(self, flag, flag_list):
        """
        Returns Flags from search list
        """
        clearline = (6 * ("",))
        self.MachO_List.append(clearline)
        name, intvalue = flag
        binary_value = ('{:026b}'.format(intvalue))
            
        counter = 0
        for flag in reversed(binary_value):
            flag = int(flag)
                
            if flag == True:
                    
                flag_name, flag_description = flag_list[counter]
                flag_name = flag_name
                flag_description = flag_description
                flag_set = "TRUE"
            else:
                    
                flag_name, flag_description = flag_list[counter]
                flag_name = flag_name
                flag_description = flag_description
                flag_set = "FALSE"
                
                
            insert = (" ", " ", "FLAG", flag_name, flag_set, flag_description)
                
            self.MachO_List.append(insert)
            counter+=1
        self.MachO_List.append(clearline)
            
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in _MACHO_HEADER_64_INFO:
            if field is item[0]:
                if hexvalue == hex(item[1]):
                    return item[2]
                            
        optional = '.'
        return optional