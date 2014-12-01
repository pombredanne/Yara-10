import mimetypes 
import struct
import re

def get_type(filename):
    """
    Get file mimetype
    """
    type = mimetypes.guess_type(filename)
    return type

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

def check_pe(handle):
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
    
def multiple_byte_handler(handle, seek, read):
    elafnew = offset = coff_elfanew(handle)
    secion_header_offset = 0xf8
    sectionoffset = (elafnew+secion_header_offset+seek)
    handle.seek(sectionoffset, 0)
    byte = handle.read(read)
    return byte, sectionoffset

def ctypes_convert(stringtype):
    offsetsize = str(stringtype)
    regex = re.compile("'.+'")
    match = re.findall(regex, offsetsize)
    match = str(match)
    return match[12:-3]
    
def get_elf_programheader_number(handle):
    handle.seek(44, 0)
    data = handle.read(2)
    data = struct.unpack("H", data)[0]
    return data

def get_endianess(handle):
    handle.seek(5, 0)
    data = handle.read(1)
    data = struct.unpack("B", data)[0]
        
    if data == 1:
        return '<'
    elif data == 2:
        return '>'
        
    
