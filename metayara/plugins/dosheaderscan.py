import struct
from metayara.metatag import _IMAGE_DOS_HEADER

class dosheaderscan():
    """
    >> DOS Header scan
    """
    
    def __init__(self, handle, DOS_list):
        self.handle = handle
        self.DOS_list = DOS_list    
        self.dos_header_file()
        
    def dos_header_file(self):
        """Returns a list with DOS header fields"""
        self.dos_image_header()
        
    def dos_image_header(self):
        for name, seek, read, pack in _IMAGE_DOS_HEADER:
            byte = self.byte_handler(self.handle, seek, read)
            key = struct.unpack(pack, byte)[0]
            hey = hex(key)
            insert = (name, "int", key, "hex value", hey)
            self.DOS_list.append(insert)
    
    def byte_handler(self, handle, seek, read):
        handle.seek(seek)
        byte = handle.read(read)
        return byte