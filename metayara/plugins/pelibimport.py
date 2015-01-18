import struct
from metayara.metatag import _SECTION_HEADER
import ctypes
import encodings
from metayara import utils
import sys
from test.test_email.test_message import first

class pelibimport():
    """
    >> Scan for imported librarys in the header
    """
    def __init__(self, handle, Lib_List):
        self.handle = handle
        self.Lib_List = Lib_List
        self.is_pe(handle)
        self.libimports(handle)
    
    def is_pe(self, handle):
        check = utils.check_pe(handle)
        if check is False:
            sys.exit("The image is not Portable Executable")
        
    def libimports(self, handle):
        """
        Set Field header
        """

        setup = ("Offset", "StringSize", "LibraryName", "Value")
        self.Lib_List.append(setup)
        
        sym_offset, sym_offset_size, virtadd, rawaddres = self.find_import_section(handle)
        
        max_offset = rawaddres+sym_offset_size
        
        raw_search = rawaddres + (sym_offset - virtadd)
        
        lib_offset_size = 0
        while True:
            handle.seek(raw_search+12+lib_offset_size , 0) #BASE VAN LIBRARY - GROTE IS 20 - AANTAL LIBRARYS LOOP
            lib_string_offset = handle.read(4)
            lib_string_offset = struct.unpack("<L", lib_string_offset)[0]
            
            if lib_string_offset == 0:
                break
           
            """Library String"""
            string_offset = lib_string_offset - virtadd
            string_offset+=rawaddres
            
            handle.seek(string_offset, 0)
            library = str()
            
            lib_size = 0
            while True:
                    local_data = handle.read(1)
                    local_data = struct.unpack("<B", local_data)[0]
                    
                    if local_data == 0:
                        
                        break
                    
                    else:
                        library+=chr(local_data)
                
            insert = (hex(string_offset), len(library), library, "")       
            self.Lib_List.append(insert)
            
            
            handle.seek(raw_search+16+lib_offset_size , 0) #BASE VAN LIBRARY - GROTE IS 20 - AANTAL LIBRARYS LOOP
            firstTrunk = handle.read(4)
            firstTrunk = struct.unpack("<L", firstTrunk)[0]
            
            firstTrunk_offset = firstTrunk - virtadd
            firstTrunk_offset+=rawaddres
            
            symbol_size = 0
            while True:
                
                flag = False
                handle.seek(firstTrunk_offset+symbol_size , 0)
                firstTrunk_RVA = handle.read(4)
                firstTrunk_RVA = struct.unpack("<L", firstTrunk_RVA)[0]
                
                
                
                firstTrunk_RVA_Offset = firstTrunk_RVA - virtadd
                firstTrunk_RVA_Offset+=rawaddres
                
                
                
                if firstTrunk_RVA_Offset >= max_offset:
                    flag = True
                    firstTrunk_RVA_Offset = firstTrunk_offset-2+symbol_size
                
                if firstTrunk_RVA == 0:
                    break
                else:
                    symbol_size+=4
                
                symbol = str()
                if firstTrunk_RVA_Offset != 0:
                    handle.seek(firstTrunk_RVA_Offset+2, 0)
                    
                    while True:
                        local_symbol = handle.read(1)
                        local_symbol = struct.unpack("<B", local_symbol)[0]
                        
                        if local_symbol == 0:
                            
                            break
                        
                        else:
                            if flag is True:
                                symbol+=str(local_symbol)
                            else: 
                                symbol+=chr(local_symbol)
                            
                
                symbol_table = (firstTrunk_RVA_Offset, len(symbol),"",symbol)       
                self.Lib_List.append(symbol_table)
            
            if lib_string_offset == 0:
                break
            else:
                 lib_offset_size+=20
                 
                
    def get_imagebase(self, handle):
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
     

    def find_import_section(self, handle):
        """
        Retrieve section information form PE
        """
        elfanew = utils.coff_elfanew(handle)
        handle.seek(elfanew+24+104, 0)
        sym_offset = handle.read(4)
        sym_offset = struct.unpack("<L", sym_offset)[0]
        
        handle.seek(elfanew+24+108, 0)
        sym_offset_size = handle.read(4)
        sym_offset_size = struct.unpack("<L", sym_offset_size)[0]
        
        handle.seek(elfanew+0x06, 0)
        byte = handle.read(0x02)
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
                        
                        rawaddres_size, realoffset = utils.multiple_byte_handler_pe(self.handle, seek+4, (ctypes.sizeof(read)))  
                        rawaddres_size = struct.unpack("<L", rawaddres_size)[0]
                        
                        virtadd, realoffset = utils.multiple_byte_handler_pe(self.handle, seek, (ctypes.sizeof(read)))  
                        virtadd = struct.unpack("<L", virtadd)[0]
                        print
                        return sym_offset, rawaddres_size, virtadd, rawaddres