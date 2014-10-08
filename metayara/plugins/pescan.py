import struct
from metayara.metatag import TAGS

class pescan():
    """
    >> PE Field header scan
    
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
    
x    pad byte        no value          
c    char            bytes of length 1    1     
b    signed char     integer    1    (1)
B    unsigned char   integer    1     
?    _Bool           bool    1    (2)
h    short           integer    2     
H    unsigned short  integer    2     
i    int             integer    4     
I    unsigned int    integer    4     
l    long            integer    4     
L    unsigned long   integer    4     
q    long long       integer    8    (3)
Q    unsigned long   long    integer    8    (3)
f    float           float    4    (4)
d    double          float    8    (4)
s    char[]          bytes         (1)
p    char[]          bytes         (1)
P    void *          integer         (5)
    """
    
    def __init__(self, handle):
        self.PE_List = {}
        self.handle = handle
        self.pe_machine(handle)
        self.pe_NumberofSections(handle)
                   
    def __repr__(self):
        return repr([self.PE_List]) 
    
    def get_header_base(self, handle):
        handle.seek(60, 0)
        byte = handle.read(4)
        header_offset=struct.unpack("<L", byte)[0]
        return header_offset
    
    def pe_machine(self, handle):
        byte = self.byte_handler(handle, 4, 2)
        machine=struct.unpack("<H", byte)[0]
        key = hex(machine)
        
        if key in TAGS: 
            self.PE_List["Machine"] = TAGS[key]
        else:
            self.PE_List.append("no key found")
            
    def pe_NumberofSections(self, handle):
        byte = self.byte_handler(handle, 6, 2)
        numberofsections = struct.unpack("<H", byte)[0]
        key = hex(numberofsections)
        self.PE_List["Sections"] = numberofsections
        
    def byte_handler(self, handle, seek, read):
        offset = self.get_header_base(handle)
        handle.seek(offset+seek)
        byte = handle.read(read)
        return byte
    
    
        
            
            
    
    