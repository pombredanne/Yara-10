import struct
from metayara.metatag import _IMAGE_DOS_HEADER

class dosheaderscan():
    """
    >> DOS Header scan
    """
    
    def __init__(self, handle, DOS_list):
        self.handle = handle
        self.DOS_list = DOS_list  
        self.set_field_header()  
        self.dos_header_file()
       
    def set_field_header(self):
        setup = ("Field", "Integer", "Hex" ,"OptionalFields")
        self.DOS_list.append(setup) 
        
    def dos_header_file(self):
        """Returns a list with DOS header fields"""
        self.dos_image_header()
        
    def dos_image_header(self):
        for name, seek, read, pack in _IMAGE_DOS_HEADER:
            byte = self.byte_handler(self.handle, seek, read)
            integer = struct.unpack(pack, byte)[0]
            hexvalue = hex(integer)
            insert = (name, integer, hexvalue)
            self.DOS_list.append(insert)
    
    def byte_handler(self, handle, seek, read):
        handle.seek(seek)
        byte = handle.read(read)
        return byte