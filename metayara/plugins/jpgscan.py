import struct
from metayara.metatag import TAGS

class jpgscan():
    """
    >> JPG field header scan
    """
    
    def __init__(self, handle):
        self.PE_List = []
        self.handle = handle
        self.aight(handle)
        
    def __repr__(self):
        return repr([self.PE_List])     
        
    def aight(self, handle):   
        self.PE_List.append("test")     
            
    
    