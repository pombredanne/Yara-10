import struct
from metayara.metatag import TAGS

class PEScan():
    """
    >> PE Field header scan
    """
    PE_List = []
    
    
    def __init__(self, handle):
        self.handle = handle
        self.pe_machine(handle)
                
    def pe_machine(self, handle):
        
        handle.seek(60, 0)
        s=handle.read(4)
        header_offset=struct.unpack("<L", s)[0]
        
        
        handle.seek(header_offset+4)
        s=handle.read(2)
        machine=struct.unpack("<H", s)[0]
        
        key = hex(machine)
        
        
        if key in TAGS:
            
            self.PE_List.append("Machine is {}".format(TAGS[key]))
        else:
            self.PE_List.append("no key found")
            
            
    
    