#!None
import sys

if sys.version_info < (3, 0, 0):
    sys.stderr.write("Requires version 3.0 or higher")
    sys.exit(1)

import optparse
import os
import re
import importlib.machinery
from metayara.constants import pluginpath
import modulefinder

sys.stderr.write("Metayara Scanning Platform\n\n")

def plugin_description():
    
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

def Output_data(dictionary): 
    """
    maxsize = max(map(len, dictionary))
    
    for line in dictionary:
        print("{0:<{1}} -  {2}".format(line, maxsize, dictionary[line]))
        """
    for name, integer, key, val, hey in dictionary:
        if name == "Magic;":
            print("\n")
        print("{0:30} {1:7} {2:10} {3:3} {4}".format(name, integer, key, val, hey))
        
def Process(cmd, filename):
    print(cmd)
    print(filename)
    """Open File buffer"""
    try:
        handle = open(filename, 'rb')
        
    except IOError as e:
        print(e)
        
    for name in os.listdir(pluginpath):
        if cmd in name:
            setdir = (pluginpath + name)
    
    dict_items = []
    loader = importlib.machinery.SourceFileLoader(cmd, setdir)
    foo = loader.load_module()
    obj = getattr(foo, cmd)
    data = obj(handle, dict_items)
    
    Output_data(dict_items)
    
    
            
def main():
    parser = optparse.OptionParser(usage="usage: %prog run [options] filename")
    parser.add_option("-f", "--filename", dest="filename", action="store", type="string",
                      help="filename to be used")
    parser.add_option("--pluginlist", dest="pluginlist", action='store_true',
                      help='show available plugins', )
    parser.add_option("-c", "--command", dest="command", action='store', type="string", 
                      help='execute command')
    
    opts, args = parser.parse_args()    
    
    if opts.pluginlist:
        
        plugins = plugin_description()
        maxsize = max(map(len, plugins))
        
        for value in plugins:
            print("{0:<{1}} - {2}".format(value, maxsize, plugins[value]))
                          
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
    