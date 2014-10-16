import struct
from metayara.metatag import TAGS
from time import gmtime, strftime
from metayara.metatag import _IMAGE_FILE_HEADER, _IMAGE_OPTIONAL_HEADER

class pescan():
    """
    >> PE Field header scan
    """
    
    def __init__(self, handle, PE_List):
        self.handle = handle
        self.PE_list = PE_List
        self.pefile()
        
    def pefile(self):
        """Returns a list with pe header fields"""
        self.pe_image_file_header(self.PE_list)
        self.pe_image_optinal_header(self.PE_list)
            
    def pe_image_file_header(self, field_list):
        for name, seek, read, pack in _IMAGE_FILE_HEADER:
            byte = self.byte_handler_pe_file_header(self.handle, seek, read)
            key = struct.unpack(pack, byte)[0]
            hey = hex(key)
            insert = (name, "int", key, "hex value", hey)
            field_list.append(insert)
        
            
    def pe_image_optinal_header(self, field_list):
        for name, seek, read, pack in _IMAGE_OPTIONAL_HEADER:
            byte = self.byte_handler_pe_file_optional_header(self.handle, seek, read)
            key = struct.unpack(pack, byte)[0]
            hey = hex(key)
            insert = (name, "int", key, "hex value", hey)
            field_list.append(insert)
    
    def get_elfanew_offset(self, handle):
        """Returns PE Header Start offset"""
        handle.seek(60, 0)
        byte = handle.read(4)
        header_offset=struct.unpack("<L", byte)[0]
        return header_offset
    
    def byte_handler_pe_file_header(self, handle, seek, read):
        """Module for byte handling pe file header"""
        offset = self.get_elfanew_offset(handle)
        handle.seek(offset+seek)
        byte = handle.read(read)
        return byte
    
    def byte_handler_pe_file_optional_header(self, handle, seek, read):
        """Module for byte handling pe file optional header"""
        offset = self.set_optinal_header_offset(handle)
        handle.seek(offset+seek)
        byte = handle.read(read)
        return byte
    
    def set_optinal_header_offset(self, handle):
        "returns integer for pe file optinal header offset"
        offset = self.get_elfanew_offset(handle)
        pe_optinal_header_offset = offset + 24
        return pe_optinal_header_offset
        
    