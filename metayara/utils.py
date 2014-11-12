import mimetypes 
import struct

def get_type(filename):
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
    handle.seek(128+24, 0)
    data =handle.read(2)
    data = struct.unpack("H", data)[0]
    
    if data == 0x10b:
        return True
    else:
        return False
    
    
    
    
