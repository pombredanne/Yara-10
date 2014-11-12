import struct
import ctypes
from metayara import utils

class libimport():
    
    
    def __init__(self, handle, Lib_List):
        self.handle = handle
        self.Lib_List = Lib_List
        self.libimport()
        
    def libimport(self):
        setup = ("Offset", "LibraryName", "Value")
        self.Lib_List.append(setup)
        self.get_imagebase()
           
    def get_imagebase(self):
        byte, realoffset = self.byte_handler(self.handle, 52, ctypes.sizeof(ctypes.c_uint32))
        intvalue = struct.unpack("<L", byte)[0]
        realoffset = hex(realoffset)
        insert = (realoffset, "Imagebase", hex(intvalue))
        self.Lib_List.append(insert)
      
    def byte_handler(self, handle, seek, read):
        """
        Module for byte handling pe file header
        """
        offset = utils.coff_elfanew(handle)
        print(offset)
        realoffset = (offset+seek)
        handle.seek(realoffset)
        byte = handle.read(read)
        return byte, realoffset    