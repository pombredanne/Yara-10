import mimetypes 
import struct
import re
from magic import magic

def get_type(filename):
    """
    Get file mimetype
    """    
    type = magic.from_file(filename)
    return type


def get_filetype(filename):
    """
    Return filetype
    """
    handle = open(filename, mode='rb')
    pe_type = check_pe(handle)
    if pe_type is True:
        return '32 Bit PE'
    else:
        elf_type = check_elf(handle)
        if elf_type is True:
            version = get_elf_bitversion(handle)
            version = str(version) + ' Bit ELF'
            return version
        else:
            macho_type = check_macho_version(handle)
            return macho_type
               
def check_macho_version(handle, check=None):
    from metayara.metatag import _MACHO_HEADER_64_INFO
    
    handle.seek(0, 0)
    macho = handle.read(4)
    macho = struct.unpack("<L", macho)[0]
    macho = hex(macho)
    
    for item in _MACHO_HEADER_64_INFO:
        if macho == hex(item[1]):
            if check is None:
                return item[2]
            else: 
                return True
            
    if check is True:
        return False
        
def coff_imagebase(handle):
    """
    Returns Imagebase
    """
    handle.seek(128+52, 0)
    data = handle.read(4)
    imagebase=struct.unpack("<L", data)[0]
    return imagebase
    
def coff_elfanew(handle):
    """
    Return Elfanew
    """
    handle.seek(60, 0)
    byte = handle.read(4)
    header_offset=struct.unpack("<L", byte)[0]
    return header_offset

def check_elf(handle):
    handle.seek(0, 0)
    elf = handle.read(4)
    type = struct.unpack("<BBBB", elf)
    if hex(type[0]) == '0x7f':
            if hex(type[1]) == '0x45':
                if hex(type[2]) == '0x4c':
                    if hex(type[3]) == '0x46':
                        return True
    else:
        return False

def check_pe(handle):
    """
    Check if file is Portable Executable
    """
    handle.seek(0, 0)
    data = handle.read(2)
    
    if data == b'MZ':
        return True
    
    handle.seek(coff_elfanew(handle), 0)
    data = handle.read(4)
    data = data.decode('utf-8', 'ignore')
    
    if data == 'PE\x00\x00':
        return True
    else:
        return False
    
def multiple_byte_handler_pe(handle, seek, read):
    """
    Byte handler for secion header
    """
    elafnew = offset = coff_elfanew(handle)
    secion_header_offset = 0xf8
    sectionoffset = (elafnew+secion_header_offset+seek)
    handle.seek(sectionoffset, 0)
    byte = handle.read(read)
    return byte, sectionoffset

def ctypes_convert(stringtype):
    """
    Convert ctypes to string for output
    """
    offsetsize = str(stringtype)
    regex = re.compile("'.+'")
    match = re.findall(regex, offsetsize)
    match = str(match)
    return match[12:-3]

def ctypes_convert_array(stringtype):
    """
    Convert ctypes to string for output
    """
    offsetsize = str(stringtype)
    regex = re.compile("'.+'")
    match = re.findall(regex, offsetsize)
    match = str(match)
    return match[12:-3]
    
def get_elf_programheader_number(handle):
    """
    Retrieve Number of Program headers 
    """
    version = get_elf_bitversion(handle)
    
    if version == 32:
        handle.seek(44, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
    
    if version == 64:
        handle.seek(56, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
        

def get_elf_programheader_entry(handle):
    """
    Retrieve Entry Program Headers
    """
    version = get_elf_bitversion(handle)
    
    if version == 32:
        handle.seek(28, 0)
        data = handle.read(4)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "L"), data)[0]
        return data
    
    if version == 64:
        handle.seek(32, 0)
        data = handle.read(8)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "LL"), data)[0]
        return data
    
    
def get_elf_programheader_entry_size(handle):
    
    version = get_elf_bitversion(handle)
    
    if version == 32:
        handle.seek(42, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
    
    if version == 64:
        handle.seek(54, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data

def get_elf_section_entry(handle):
    """
    Retrieve Entry Section Header
    """
    
    version = get_elf_bitversion(handle)
    if version == 32:
        
        handle.seek(32, 0)
        data = handle.read(4)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "L"), data)[0]
        return data
    
    if version == 64:
        
        handle.seek(40, 0)
        data = handle.read(8)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "LL"), data)[0]
        return data

def get_elf_section_entry_size(handle):
    """
    Retrieve Size of Section header
    """
    version = get_elf_bitversion(handle)
    if version == 32:
    
        handle.seek(46, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
    if version == 64:
        
        handle.seek(58, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
        

def get_elf_section_count(handle):
    """
    Retrieve Number ofSection header
    """
    version = get_elf_bitversion(handle)
    if version == 32:
        
        handle.seek(48, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data
    
    if version == 64:
        
        handle.seek(60, 0)
        data = handle.read(2)
        endian = get_endianess(handle)
        data = struct.unpack((endian + "H"), data)[0]
        return data

def get_elf_shtrtable_index(handle):
    """
    Retrieve Section header string table
    """
    handle.seek(50, 0)
    data = handle.read(2)
    endian = get_endianess(handle)
    data = struct.unpack((endian + "H"), data)[0]
    return data

def get_elf_sthrtable_entry(handle):
    index = get_elf_shtrtable_index(handle)
    

def get_endianess(handle):
    """
    Retrieve Endianess for ELF header
    """
    handle.seek(5, 0)
    data = handle.read(1)
    data = struct.unpack("B", data)[0]
        
    if data == 1:
        return '<'
    elif data == 2:
        return '>'
        
def get_elf_bitversion(handle):
    """
    Check Bit version ELF header
    """
    endian = get_endianess(handle)
    handle.seek(4, 0)
    version = handle.read(1)
    version = struct.unpack(endian + "B", version)[0]
    if version == 1:
        return 32
    else:
        return 64
    
def get_macho_loadcommands_64(handle):
    handle.seek(16, 0)
    data = handle.read(4)   
    data = struct.unpack("<L", data)[0]
    return data
    
