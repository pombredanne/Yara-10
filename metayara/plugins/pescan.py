import struct
from metayara.metatag import TAGS
from time import gmtime


class pescan():
    """


    USHORT E_MAGIC
    USHORT E_CBLP
    USHORT E_CP
    USHORT E-CRLC

    >> PE Field header scan
    Start Byte 60
    USHORT  Machine; 2 H                            - 64 R 2
    USHORT  NumberOfSections; 2 H                   - 66 R 2
    ULONG   TimeDateStamp; 4 L                      - 68 R 4
    ULONG   PointerToSymbolTable; 4L                - 72 R 4
    ULONG   NumberOfSymbols; 4 L                    - 76 R 4
    USHORT  SizeOfOptionalHeader; 2H                - 80 R 2
    USHORT  Characteristics; 2H                     - 82 R 2
    
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


USHORT magic                   2H                   - 84 R 2
UCHAR MajorLinkedVersion       1B                   - 86 R 1
UCHAR MinorLinkedVersion       1B                   - 87 R 1
ULONG SizeofCode               4L                   - 88 R 4
ULONG SizeofInitializedData    4L                   - 92 R 4
ULONG SizeofUninitializedData  4L                   - 96
ULONG AddressofEntryPoint      4L                   - 100
ULONG BaseofCode               4L                   - 104
ULONG BaseofData               4L                   - 108

ULONG ImageBAse                4L                   - 112 R 4


    """
    
    def __init__(self, handle):
        self.PE_List = {}
        self.handle = handle
        self.pe_machine(handle)
        self.pe_NumberofSections(handle)
        self.pe_TimeDateStamp(handle)
        self.pe_PointerToSymbolsTable(handle)
        self.pe_NumberOfSymbols(handle)
        self.pe_SizeOfOptionalHeader(handle)
        self.pe_Characteristics(handle)
        #self.pe_ImageBase(handle)
        self.pe_emagic(handle)

                   
    def __repr__(self):
        return repr([self.PE_List]) 


    def pe_emagic(self, handle):
        handle.seek(1, 0)
        byte = handle.read(2)
        e_magic = struct.unpack("<H", byte)[0]
        self.PE_List["Magic Number"] = e_magic

    def get_header_base(self, handle):
        handle.seek(60, 0)
        byte = handle.read(4)
        header_offset=struct.unpack("<L", byte)[0]
        return header_offset

    def get_header_base_op(self, handle, base):
        handle.seek(base, 0)
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

    def byte_handler_op(self, handle, seek, read, base):
        offset = self.get_header_base_op(handle, base)
        handle.seek(offset+seek)
        byte = handle.read(read)
        return byte
    
    def pe_TimeDateStamp(self, handle):

    	byte = self.byte_handler(handle, 8, 4)
    	timedatestamp = struct.unpack("<L", byte)[0]
    	#time = ("%Y, %M, %D, %H, %M, %S, %D, %Y, &I).format(timedatestamp)
    	self.PE_List["Time Date Stamp"] = timedatestamp
    			   
    def pe_PointerToSymbolsTable(self, handle):
    	byte = self.byte_handler(handle, 12, 4)
    	pointertable = struct.unpack("<L", byte)[0]
    	self.PE_List["Pointer To Symbol Table"] = pointertable
    	
    def pe_NumberOfSymbols(self, handle):
    	byte = self.byte_handler(handle, 16, 4)
    	NumberOfSymbols = struct.unpack("<L", byte)[0]
    	self.PE_List["Number Of Symbols"]= NumberOfSymbols
    	
    def pe_SizeOfOptionalHeader(self, handle):
    	byte = self.byte_handler(handle, 20, 2)
    	SizeOfOptionalHeader = struct.unpack("<H", byte)[0]
    	self.PE_List["Size Of Optional Header"] = SizeOfOptionalHeader
    	
    def pe_Characteristics(self, handle):
    	byte = self.byte_handler(handle, 22, 2)
    	Characteristics = struct.unpack("<H", byte)[0]
    	self.PE_List["Characteristics"] = Characteristics
    
    def pe_ImageBase(self, handle):
        byte = self.byte_handler_op(handle, 28, 4, 84)
        imagebase = struct.unpack("<L", byte)[0]
        self.PE_List["ImageBase"] = imagebase


            
    
    