import struct
from metayara.metatag import _IMAGE_DOS_HEADER, _DOS_HEADER_INFO
import ctypes
import sys
import re
from metayara import utils

class dosheader():
    """
    >> DOS Header scan
    """
    def __init__(self, handle, DOS_list):
        self.handle = handle
        self.DOS_list = DOS_list  
        self.is_pe(handle)
        self.set_field_header()  
        self.dos_header_file()
        
        
    def is_pe(self, handle):
        check = utils.check_pe(handle)
        if check is False:
            sys.exit("The image is not Portable Executable")
            
    def check_tags(self, field, hexvalue):
        """
        Check for tags in metatag.tag
        """
        for item in _DOS_HEADER_INFO:
            if field is item[0]:
                if hexvalue == hex(item[1]):
                    return item[2]
                            
        optional = '.'
        return optional
       
    def set_field_header(self):
        """
        Set header list
        """
        setup = ("Offset", "Type", "Field", "Integer", "Hexadecimal" ,"OptionalFields")
        self.DOS_list.append(setup) 
        
    def dos_header_file(self):
        """
        Returns a list with DOS header fields
        """
        self.dos_image_header()
        
    def dos_image_header(self):
        """
        Retrieve Dos information from handle
        """
        for name, seek, read, pack in _IMAGE_DOS_HEADER:
            byte, realoffset = self.byte_handler(self.handle, seek, ctypes.sizeof(read))
            integer = struct.unpack(pack, byte)[0]
            hexvalue = hex(integer)
            realoffset = hex(realoffset)
            set_optional_field = self.check_tags(name, hexvalue)
            insert = (realoffset, utils.ctypes_convert(read), name, integer, hexvalue, set_optional_field)
            self.DOS_list.append(insert)
    
    def byte_handler(self, handle, seek, read):
        """
        Retrieve Offset and Byte from handle
        """
        handle.seek(seek)
        realoffset = seek
        byte = handle.read(read)
        return byte, realoffset
    
    