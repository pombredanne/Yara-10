import struct
from metayara.metatag import _SECTION_HEADER
import ctypes
import encodings
from metayara import utils

class pelibimport():
    """
    >> Scan for imported library's in the header
    """
    def __init__(self, handle, Lib_List):
        self.handle = handle
        self.Lib_List = Lib_List
        self.is_pe(handle)
        self.libimports()
    
    def is_pe(self, handle):
        check = utils.check_pe(handle)
        if check is False:
            sys.exit("The image is not Portable Executable")
        
    def libimports(self):
        setup = ("Offset", "Size of Offset", "LibraryName", "Value")
        self.Lib_List.append(setup)
        imagebase = self.get_imagebase()
        virtualaddress, rawaddress = self.find_import_section()
        virtbase = virtualaddress + imagebase
        add_bytes = 0
 
        while True:
            if add_bytes == 0:
               pass  
            self.handle.seek(rawaddress+12+add_bytes, 0)
            data = self.handle.read(4)
            data = struct.unpack("<L", data)[0]
                
            d = int(data)
            """
            If section is not filled with 0 bytes
            """
            if d != 0:
                nextseek= (virtbase - d)
                finalseek= (imagebase - nextseek)
                finalseekoffset= (rawaddress + finalseek)
                   
                self.handle.seek(finalseekoffset, 0)
                x = 1
                section = str()
                while True:
                    data = self.handle.read(x)
                    data = struct.unpack("B", data)[0]
                    
                    if data == 0:
                        break
                    else:
                        section+=chr(data)
                
                insert = (hex(finalseekoffset), len(section), section.lower())
                self.Lib_List.append(insert)
                
            else:
                break
            add_bytes+=20
             
    def get_imagebase(self):
        byte, realoffset = self.byte_handler(self.handle, 52, ctypes.sizeof(ctypes.c_uint32))
        intvalue = struct.unpack("<L", byte)[0]
        realoffset = hex(realoffset)
        return intvalue
      
    def byte_handler(self, handle, seek, read):
        """
        Module for byte handling pe file header
        """
        offset = utils.coff_elfanew(handle)
        realoffset = (offset+seek)
        handle.seek(realoffset)
        byte = handle.read(read)
        return byte, realoffset    
    
    def find_import_section(self):
        offset = offset = utils.coff_elfanew(self.handle)
        self.handle.seek(offset+0x06, 0)
        byte = self.handle.read(0x02)
        sectionheader_size = 40
        Sectionnumbers = struct.unpack("<H", byte)[0]
        
        additional_bytes = int()
        for x in range(Sectionnumbers):
            
            if x> 0:
                additional_bytes+= sectionheader_size
                
            for field, seek, read, pack in _SECTION_HEADER:
                if field == str('Name;'):
                    if additional_bytes > 0:
                        seek+=additional_bytes
                    byte, realoffset = utils.multiple_byte_handler(self.handle, seek, (8 *ctypes.sizeof(read)))
                    sectionname = struct.unpack(pack, byte)
                    realoffset = int(realoffset)
                    """
                    Convert int to ASCII
                    """ 
                    section = str()
                    
                    for char in byte:
                        if char>0:
                            section+=chr(char)
                   
                    if section == ".idata":
                        virtadd = realoffset+12
                        self.handle.seek(virtadd, 0)
                        virtdata = self.handle.read(ctypes.sizeof(ctypes.c_uint32))
                        virtdata = struct.unpack("<L", virtdata)[0]
                        
                        rawadd = realoffset+20
                        self.handle.seek(rawadd, 0)
                        rawdata = self.handle.read(ctypes.sizeof(ctypes.c_uint32))
                        rawdata = struct.unpack("<L", rawdata)[0]
                        return virtdata, rawdata