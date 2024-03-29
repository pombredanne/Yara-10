import struct
from time import gmtime, strftime
from metayara.metatag import _IMAGE_FILE_HEADER, _IMAGE_OPTIONAL_HEADER, tag_pe, _PE_Characteristics, _PE_DDLCharacteristics, _IMAGE_OPTIONAL_HEADER_64
import ctypes, sys
import importlib
from metayara import utils

class peheader():
    """
    >> PE Field header scan - Only supports 32Bit applications for now
    """

    def __init__(self, handle, PE_List):
        self.handle = handle
        self.PE_list = PE_List
        self.is_pe(handle)
        self.set_field_header()
        self.pefile()
    
    def is_pe(self, handle):
        check = utils.check_pe(handle)
        if check is False:
            sys.exit("The image is not Portable Executable")
            
        
    def pefile(self):
        """
        Returns a list with pe header fields
        """
        self.pe_image_file_header(self.PE_list)
        self.pe_image_optional_header(self.PE_list)
    
    def set_char_flags(self, flag, flag_list):
        """
        Returns Flags from search list
        """
        clearline = (6 * ("",))
        self.PE_list.append(clearline)
        name, intvalue = flag
        binary_value = ('{:016b}'.format(intvalue))
        
        counter = 0
        for flag in reversed(binary_value):
            flag = int(flag)
            
            if flag == True:
                
                flag_name, flag_description = flag_list[counter]
                flag_name = flag_name
                flag_description = flag_description
                flag_set = "TRUE"
            
            
            
                insert = (" ", " ", "FLAG", flag_name, flag_set, flag_description)
                
                self.PE_list.append(insert)
            counter+=1
        self.PE_list.append(clearline)
        
    def set_field_header(self):
        """
        Set Field header
        """
        setup = ("Offset", "Type", "Field", "Integer Value", "Hex Value", "Optional Field")
        self.PE_list.append(setup)
        
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in tag_pe:
            if field is item[0]:
                if hexvalue == hex(item[1]):
                    return item[2]
                            
        optional = '.'
        return optional
            
    def pe_image_file_header(self, field_list):
        """
        retrieve PE header 
        """
        
        
        
        for field, seek, read, pack in _IMAGE_FILE_HEADER:
            byte, realoffset = self.byte_handler_pe_file_header(self.handle, seek, ctypes.sizeof(read))
            intvalue = struct.unpack(pack, byte)[0]
            hexvalue = hex(intvalue)
            set_optional_field = self.check_tags(field, hexvalue)
            realoffset = hex(realoffset)
            insert = (realoffset, utils.ctypes_convert(read), field, intvalue, hexvalue, set_optional_field)
            
            if field == "Characteristics;":
                set_char_flag = (field, intvalue)
            
            field_list.append(insert)   
             
        if set_char_flag is not None:
            self.set_char_flags(set_char_flag, _PE_Characteristics)  
        
    def pe_image_optional_header(self, field_list):
        """
        Retrieve PE Optional header information
        """
        
        byte, realoffset = self.byte_handler_pe_file_optional_header(self.handle, 0, 2)
        bit_version = struct.unpack("<H", byte)[0]
        
        
        if hex(bit_version) == '0x20b':
            
            _OPTIONAL_HEADER = _IMAGE_OPTIONAL_HEADER_64
        
        if hex(bit_version) == '0x10b':
            _OPTIONAL_HEADER = _IMAGE_OPTIONAL_HEADER
        
        
        for field, seek, read, pack in _OPTIONAL_HEADER:
            byte, realoffset = self.byte_handler_pe_file_optional_header(self.handle, seek, ctypes.sizeof(read))
            intvalue = struct.unpack(pack, byte)[0]
            hexvalue = hex(intvalue)
            set_optional_field = self.check_tags(field, hexvalue)
            realoffset = hex(realoffset)
            insert = (realoffset, utils.ctypes_convert(read), field, intvalue, hexvalue, set_optional_field)  

            field_list.append(insert)
            if field == "DLLCharacteristics;":
                set_dllchar_flag = (field, intvalue)
                self.set_char_flags(set_dllchar_flag, _PE_DDLCharacteristics)
    
    def byte_handler_pe_file_header(self, handle, seek, read):
        """
        Module for byte handling pe file header
        """
        offset = offset = utils.coff_elfanew(handle)
        realoffset = (offset+seek)
        handle.seek(realoffset)
        byte = handle.read(read)
        return byte, realoffset
    
    def byte_handler_pe_file_optional_header(self, handle, seek, read):
        """
        Module for byte handling pe file optional header
        """
        offset = self.set_optional_header_offset(handle)
        handle.seek(offset+seek)
        realoffset = (offset+seek)
        byte = handle.read(read)
        return byte, realoffset
    
    def set_optional_header_offset(self, handle):
        """
        returns integer for pe file optinal header offset
        """
        offset = offset = utils.coff_elfanew(handle)
        pe_optinal_header_offset = offset + 24
        return pe_optinal_header_offset
        
    