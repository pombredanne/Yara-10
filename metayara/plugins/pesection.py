import struct
from metayara.metatag import _SECTION_HEADER, _SECTION_FLAG
from metayara import utils
import sys
import ctypes

class pesection():
    """
    >> PE Section Header scan module
    """
    def __init__(self, handle, PE_List):
        self.handle = handle
        self.PE_List = PE_List
        self.is_pe(handle)
        self.set_field_header()
        self.pe_section()
        
        
    def is_pe(self, handle):
        check = utils.check_pe(handle)
        if check is False:
            sys.exit("The image is not Portable Executable")
            
    def set_field_header(self):
        """
        Set Field Header
        """
        setup = ("Offset", "Type", "Section Name", "Field Name", "Integer Value", "Hex Value")
        self.PE_List.append(setup)

    def pe_section(self):
        self.pe_image_section_header(self.PE_List)
    
    def pe_image_section_header(self, field_list):
        """
        Retrieve Section Number
        """
        offset = offset = utils.coff_elfanew(self.handle)
        self.handle.seek(offset+0x06, 0)
        byte = self.handle.read(0x02)
        sectionheader_size = 40
        Sectionnumbers = struct.unpack("<H", byte)[0]
        
        additional_bytes =int()
        for x in range(Sectionnumbers):
            
            if x> 0:
                """
                Add setion header size for next section 
                """
                additional_bytes+= sectionheader_size
                
            for field, seek, read, pack in _SECTION_HEADER:
                """
                retrieve PE section header 
                """
                if field == str('Name;'):
                    if additional_bytes > 0:
                        seek+=additional_bytes
                    byte, realoffset = self.multiple_byte_handler_pe(self.handle, seek, (8 * ctypes.sizeof(read)))
                    sectionname = struct.unpack(pack, byte)
                    realoffset = hex(realoffset)
                    """
                    Convert int to ASCII
                    """
                    section = str()
                   
                    for char in byte:
                        if char>0:
                            section+=chr(char)
                    insert = (realoffset, utils.ctypes_convert(read), section,  str(), str(), str())
                    field_list.append(insert)  
                    
                else:
                    if additional_bytes > 0:
                        seek+=additional_bytes
                    byte, realoffset = self.byte_handler_sectionheader(self.handle, seek, ctypes.sizeof(read))
                    intvalue = struct.unpack(pack, byte)[0]
                    hexvalue = hex(intvalue)
                    realoffset = hex(realoffset)
                    
                    insert = (realoffset, utils.ctypes_convert(read), str(), field, intvalue, hexvalue)
                    field_list.append(insert)  
                    local_counter = int()
                    if field == str("Characteristics;"):
                        bin_value = ('{:032b}'.format(intvalue))
                        clearline = (6 * ("",))
                        field_list.append(clearline)
                        
                        for flag in reversed(bin_value):
                            if 20 <= local_counter < 24:
                                pass
                                """
                                Section for Alignment
                                """
                            else:
                                flag = int(flag)
                                if flag == True:
                                    
                                    flag_name = _SECTION_FLAG[local_counter]
                                    flag_set = "TRUE"
                                    insert = ("", "", "FLAG", flag_name, flag_set, "")
                                    field_list.append(insert)
                            local_counter+=1
                        clearline = (6 * ("",))
                        field_list.append(clearline)
        
            
    def multiple_byte_handler_pe(self, handle, seek, read):
        """
        Byte handling for PE section offset
        """
        elafnew = offset = utils.coff_elfanew(handle)
        secion_header_offset = 0xf8
        sectionoffset = (elafnew+secion_header_offset+seek)
        handle.seek(sectionoffset, 0)
        byte = handle.read(read)
        return byte, sectionoffset
                  
    def byte_handler_sectionheader(self, handle, seek, read):
        """
        Module for byte handling pe file header
        """
        offset = offset = utils.coff_elfanew(handle)
        realoffset = (offset+seek+0xf8)
        handle.seek(realoffset)
        byte = handle.read(read)
        return byte, realoffset
    
    def get_elfanew_offset(self, handle):
        """
        Returns PE Header Start offset
        """
        handle.seek(60, 0)
        byte = handle.read(4)
        header_offset=struct.unpack("<L", byte)[0]
        return header_offset