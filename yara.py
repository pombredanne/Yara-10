#!pythonss2
import sys
"""Version Checker"""
if sys.version_info < (3, 0, 0):
    sys.stderr.write("Requires version 3.0 or higher")
    sys.exit(1)
    
from time import gmtime, strftime
import os
from metayara.constants import PLUGINPATH
import optparse
import re


sys.stderr.write("Metayara Scanning Platform\n\n")
    
"""
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

def Process(command, file, plugins):
    """ Strip list"""
    filename = str(file)    
    filename = filename.strip('[]')
    filename = filename.strip("''")
    """Ready Plugin list for import"""
    for plugin in plugins:
        print(plugin)
    
    
    handle = open(filename, mode='rb')
    handle.close()
    #obj = pescan.PEScan(handle)
    #print(obj.PE_List)
    

def meta_machine(handle):
    print(type(handle))
    
def plugin_description():
    
    regex = re.compile(">>.+")   
    pluginlist = []
    plugindescription = []
    
    for item in os.listdir(path=PLUGINPATH):
        if item.endswith(".py"):
            pluginlist.append(PLUGINPATH + item)
             
    for plugin in pluginlist:
        file = open(plugin, 'r')
        
        plugindescription.append(plugin)
        for _line in file:
            match = re.findall(regex, _line)
            if match:
                plugindescription.append(match)
    return plugindescription

def main():
    
    parser = optparse.OptionParser(usage="usage: %prog run [options] filename")
    parser.add_option("--pluginlist", dest="pluginlist", action='store_true',
                      help='show available plugins', )
    parser.add_option("-c", "--command", dest="command", action='store',
                      help='execute command')
    
    opts, file = parser.parse_args()
    
    plugins = plugin_description()
    
    if opts.pluginlist == True:
        
        print("Available Plugins")
        for plugin in plugins:
            print(plugin)
    
    if file:
        Process(opts.command, file, plugins)
    
    #print(opts.pluginlist)
    print("Opening File {}".format(file))

    """
    for pointer in TAGS:
        print(pointer, TAGS[pointer])
    
    filename = sys.argv[1]
    
    handle = open(filename, mode='rb')
    handle.seek(60, 0)
    s=handle.read(4)
    
    header_offset=struct.unpack("<L", s)[0]
    
    offset = binascii.hexlify(s[::-1])
    offset = int(offset, 16)
    
    print(header_offset)
    print(offset)
    
    handle.seek(header_offset+4)
    
    s=handle.read(2)
    machine=struct.unpack("<H", s)[0]
    print(machine)
    print(hex(machine))
    key = hex(machine)
    print(type(key))
    
    if key in TAGS:
        print(key)
        print("Machine is {}".format(TAGS[key]))
    else:
        print("no key found")
       
    handle.seek(offset+8, 0)
    dword = handle.read(4)
    
    t = struct.unpack(">L", dword[::-1])[0]
    print(strftime('%Y-%m-%d %H:%M:%S', gmtime(float(t))))
    
    handle.seek(header_offset+6, 0)
    x = handle.read(2)
    machine2=struct.unpack("<H", x)[0]
    print('NumberOfSections {}'.format(machine2))
    
    meta_machine(handle)
    handle.close()
    
    cmds = list_plugins()
    print(cmds)
    
    print(dir(pescan))
    """
    
    
    
if __name__ == "__main__": 
    try:
        main()
    except KeyboardInterrupt as e:
        print(e)
    

    
