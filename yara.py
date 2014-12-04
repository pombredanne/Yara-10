#!Not Set
import sys
"""
Check python version
"""
if sys.version_info < (3, 0, 0):
    sys.stderr.write("Requires version 3.0 or higher")
    sys.exit(1)
    
import ctypes
import optparse
import os
import re
import importlib.machinery
from metayara.constants import pluginpath
from metayara import utils

sys.stderr.write("Metayara Scanning Platform\n\n")

def plugin_description():
    """
    Retrieve Plugin Information from files
    """
    regex = re.compile(">>.+")
    pluginlist = []
    plugindescription = {}
    
    for item in os.listdir(path=pluginpath):
        if item.endswith(".py"):
            pluginlist.append(item)
    
    for plugin in pluginlist:

        file = open(pluginpath + plugin, 'r')
        
        for line in file:

            match = re.findall(regex, line)
        
            if match:
                match = str(match)
                plugin = re.sub(r'\.py$', '', plugin)
                match = match.strip("['>>]").strip()
                plugindescription[plugin] = match
               
    return plugindescription
    
def Output_data(container): 
    """
    Output all data from list
    """ 
    data = container[0]
    length_container_header = len(container[0])
    lenght_container_total = len(container) -1
    lenght_container_body = len(container[1])
    
    """
    Get Lenghts of Container items per column
    """
    container_lenght_list = [max(map(len, map(str, x))) for x in zip(*container)]
    
    header_field = []
    for field in data[0:length_container_header]:
        header_field.append(field)
          
    fmt = ' '.join('{:<%s}' %l for l in container_lenght_list)
    
    print(fmt.format(*container[0]))  #Header
    print('-' * (sum(container_lenght_list) + len(container_lenght_list))) #HeaderDivider
    for argv in container[1:]: #Body
        print(fmt.format(*argv))
    
      
def Process(cmd, filename):
    """
    Execute commands from parser option
    """
    
    
    print("Executing command:", cmd, "\n")
    type = utils.get_type(filename)
    print("Reading file:", filename)
    print("MIMEtype    :",  type, "\n")
    

    """
    Open IO File buffer
    """
    try:
        handle = open(filename, 'rb')
        
    except IOError as e:
        print(e)
        
    for name in os.listdir(pluginpath):
        if cmd in name:
            setdir = (pluginpath + name)
    
    container = []
    loader = importlib.machinery.SourceFileLoader(cmd, setdir)
    foo = loader.load_module()
    obj = getattr(foo, cmd)
    data = obj(handle, container)
    
    if len(container) <= 0:
        sys.stderr.write("Container Empty")
        sys.exit()
    else:
        Output_data(container)
            
def main():
    """
    Parser Options
    """
    parser = optparse.OptionParser(usage="usage: %prog run [options] filename")
    parser.add_option("-f", "--filename", dest="filename", action="store", type="string",
                      help="filename to be used")
    parser.add_option("-p", "--pluginlist", dest="pluginlist", action='store_true',
                      help='show available plugins', )
    parser.add_option("-c", "--command", dest="command", action='store', type="string", 
                      help='execute command')
    
    opts, args = parser.parse_args()    
    """
    Print Plugin info if called, otherwise execute command
    """
    if opts.pluginlist:
        
        plugins = plugin_description()
        maxsize = max(map(len, plugins))
        
        for value in plugins:
            print("{0:<{1}} - {2}".format(value, maxsize, plugins[value]))
  
    else:                
        if opts.filename is not None:
            if not os.path.exists(opts.filename):
                print("File does not exist")
                sys.exit(1)
            else:
                Process(opts.command, opts.filename)
        else:
            print("No file input")
            
   
if __name__ == "__main__": 
    try:
        main()
    except KeyboardInterrupt as e:
        print(e)
    