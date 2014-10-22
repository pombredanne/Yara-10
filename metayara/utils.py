import mimetypes 

def get_type(filename):
    type = mimetypes.guess_type(filename)
    return type