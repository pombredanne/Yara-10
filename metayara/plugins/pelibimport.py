import struct
from metayara.metatag import _SECTION_HEADER
import ctypes
import encodings
from metayara import utils

class pelibimport():
    """
    >> Scan for imported librarys in the header
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
        """
        Set Field header
        """
        lib_size = 0
        setup = ("Offset", "StringSize", "LibraryName", "Value")
        self.Lib_List.append(setup)
        imagebase = self.get_imagebase()
        SymtblOffset, rawaddress, virtadd = self.find_import_section()
        
        a = SymtblOffset - virtadd
        
       
        
        
        virtbase = SymtblOffset + imagebase
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
                
                insert = (hex(finalseekoffset), len(section), section.lower(), "")
                self.Lib_List.append(insert)
                
                
                # VINDEN VAN IMPORT TBL - PROTOTYPE - vervang oude
                t1 = virtbase - 61440
                t2 = imagebase - t1
                t3 = rawaddress + t2
                
                
                sym_size = 0
                while True:
                    self.handle.seek(rawaddress+16+lib_size , 0) #BASE VAN LIBRARY - GROTE IS 20 - AANTAL LIBRARYS LOOP
                    data = self.handle.read(4)
                    data = struct.unpack("<L", data)[0]
                    trunkRVA = virtbase - int(data)
                    trunkRVA = imagebase - trunkRVA
                    trunkRVA = rawaddress + trunkRVA
                    SymStringRva = trunkRVA
                    
                    self.handle.seek(int(trunkRVA+sym_size), 0) #SymbolAddres - GROTE IS 4
                    trunkRVA = self.handle.read(4)
                    trunkRVA = struct.unpack("<L", trunkRVA)[0]
                    
                    if hex(trunkRVA) == '0x0':
                        lib_size+=20
                        break
                    
                    SymTblRVA = virtbase - int(trunkRVA)
                    SymTblRVA = imagebase - SymTblRVA
                    SymTblRVA = rawaddress + SymTblRVA +2    
                    sym_size+=4
                
                    self.handle.seek(SymTblRVA, 0)
                    x = 1
                    section = str()
                    while True:
                        data = self.handle.read(x)
                        data = struct.unpack("<B", data)[0]
                        
                        if data == 0:
                            break
                        else:
                            section+=chr(data)
                    insert = (hex(finalseekoffset), len(section), "", section.lower())
                    self.Lib_List.append(insert)
                
            else:
                break
            add_bytes+=20
             
    def get_imagebase(self):
        """
        returns imagebase offset from PE
        """
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
     
    def get_import_table_rva(self, handle):
        offset = offset = utils.coff_elfanew(handle)
        imagebase = self.get_imagebase()
        handle.seek(offset+24+0x68)
        virtadd = handle.read(4)
        virtadd = struct.unpack("<L", virtadd)[0]
        return virtadd
         
    def find_import_section(self):
        """
        Retrieve section information form PE
        """
        offset = offset = utils.coff_elfanew(self.handle)
        sym_offset = self.get_import_table_rva(self.handle)
        
        self.handle.seek(offset+0x06, 0)
        byte = self.handle.read(0x02)
        sectionheader_size = 40
        Sectionnumbers = struct.unpack("<H", byte)[0]
        
        additional_bytes = int()
        for x in range(Sectionnumbers):
            
            if x> 0:
                additional_bytes+= sectionheader_size
                
            for field, seek, read, pack in _SECTION_HEADER: 
                if field == str('VirtualAddress;'):
                    
                    if additional_bytes > 0:
                        seek+=additional_bytes
                        
                    byte, realoffset = utils.multiple_byte_handler_pe(self.handle, seek, (ctypes.sizeof(read)))
                    sectionAdddres = struct.unpack(pack, byte)[0]
                    
                    byte, realoffset = utils.multiple_byte_handler_pe(self.handle, seek+40, (ctypes.sizeof(read)))
                    sectionNext = struct.unpack(pack, byte)[0]
                                  
                    if sectionAdddres <= sectionNext > sym_offset:
                        rawaddres, realoffset = utils.multiple_byte_handler_pe(self.handle, seek+8, (ctypes.sizeof(read)))  
                        rawaddres = struct.unpack("<L", rawaddres)[0]
                        virtadd, realoffset = utils.multiple_byte_handler_pe(self.handle, seek, (ctypes.sizeof(read)))  
                        virtadd = struct.unpack("<L", virtadd)[0]
                        return sym_offset, rawaddres, virtadd