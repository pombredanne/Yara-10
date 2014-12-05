import ctypes

"""
Structures
"""

tag_pe = [('Machine;',             0x14c,       'IMAGE_FILE_MACHINE_I386'                   ),
          ('Machine;',             0x0200,      'IMAGE_FILE_MACHINE_IA64'                   ),
          ('Machine;',             0x8664,      'IMAGE_FILE_MACHINE_AMD64'                  ),
          ('Machine;',             0x0,         'IMAGE_FILE_MACHINE_UNKNOWN'                ),
          ('Machine;',             0x1d3,       'IMAGE_FILE_MACHINE_AM33'                   ),
          ('Machine;',             0x1c0,       'IMAGE_FILE_MACHINE_ARM'                    ),
          ('Machine;',             0x1c4,       'IMAGE_FILE_MACHINE_ARMNT'                  ),
          ('Machine;',             0xaa64,      'IMAGE_FILE_MACHINE_ARM64'                  ),
          ('Machine;',             0xebc,       'IMAGE_FILE_MACHINE_EBC'                    ),
          ('Machine;',             0x200,       'IMAGE_FILE_MACHINE_IA64'                   ),
          ('Machine;',             0x9041,      'IMAGE_FILE_MACHINE_M32R'                   ),
          ('Machine;',             0x266,       'IMAGE_FILE_MACHINE_MIPS16'                 ),
          ('Machine;',             0x366,       'IMAGE_FILE_MACHINE_MIPSFPU'                ),
          ('Machine;',             0x466,       'IMAGE_FILE_MACHINE_MIPSFPU16'              ),
          ('Machine;',             0x1f0,       'IMAGE_FILE_MACHINE_POWERPC'                ),
          ('Machine;',             0x1f1,       'IMAGE_FILE_MACHINE_POWERPCFP'              ),
          ('Machine;',             0x166,       'IMAGE_FILE_MACHINE_I386'                   ),
          ('Machine;',             0x14c,       'IMAGE_FILE_MACHINE_R4000'                  ),
          ('Machine;',             0x1a2,       'IMAGE_FILE_MACHINE_SH3'                    ),
          ('Machine;',             0x1a3,       'IMAGE_FILE_MACHINE_SH3DSP'                 ),
          ('Machine;',             0x1a6,       'IMAGE_FILE_MACHINE_I386'                   ),
          ('Machine;',             0x14c,       'IMAGE_FILE_MACHINE_SH4'                    ),
          ('Machine;',             0x1a8,       'IMAGE_FILE_MACHINE_SH5'                    ),
          ('Machine;',             0x1c2,       'IMAGE_FILE_MACHINE_THUMB'                  ),
          ('Machine;',             0x169,       'IMAGE_FILE_MACHINE_WCEMIPSV2'              ),
          
          ('Subystem;',            0,           'IMAGE_SUBSYSTEM_UNKNOWN'                   ),
          ('Subystem;',            1,           'IMAGE_SUBSYSTEM_NATIVE'                    ),
          ('Subsystem;',           2,           'IMAGE_SUBSYSTEM_WINDOWS_GUI'               ),
          ('Subsystem;',           3,           'IMAGE_SUBSYSTEM_WINDOWS_CUI'               ),
          ('Subsystem;',           5,           'OS2_CUI'                                   ),
          ('Subsystem;',           7,           'IMAGE_SUBSYSTEM_POSIX_CUI'                 ),
          ('Subystem;',            9,           'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI'            ),
          ('Subystem;',            10,          'IMAGE_SUBSYSTEM_EFI_APPLICATION'           ),
          ('Subystem;',            11,          'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER'   ),
          ('Subystem;',            12,          'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER'        ),
          ('Subystem;',            13,          'IMAGE_SUBSYSTEM_EFI_ROM'                   ),
          ('Subystem;',            14,          'XBOX'                                      ),
          
          ('Magic;',               0x10b,      'IMAGE_NT_OPTIONAL_HDR32_MAGIC'             ),
          ('Magic;',               0x20b,      'IMAGE_NT_OPTIONAL_HDR64_MAGIC+'            ),
          ('Magic;',               0x107,      'IMAGE_ROM_OPTIONAL_HDR_MAGIC+'            ),]
       

_DOS_HEADER_INFO = [('e_magic', 0x5A4D,       'MZ'),
                    ('e_magic', 0x454E,       'NE'),
                    ('e_magic', 0x454C,       'LE'),
                    ('e_magic', 0x00004550,   'PE00'),]

_PE_Characteristics = [('IMAGE_FILE_RELOCS_STRIPPED',           'Relocation information was stripped from the file.'), 
                       ('IMAGE_FILE_EXECUTABLE_IMAGE',          'The file is executable'),
                       ('IMAGE_FILE_LINE_NUMS_STRIPPED',        'COFF line numbers stripped'),
                       ('IMAGE_FILE_LOCAL_SYMS_STRIPPED',       'COFF symbol table entries stripped'),
                       ('IMAGE_FILE_AGGRESSIVE_WS_TRIM',        'Aggressively trim the working set'),
                       ('IMAGE_FILE_LARGE_ADDRESS_ AWARE',      'The application can handle addresses larger than 2 GB'),
                       ('RESERVED',                             'RESERVED'),
                       ('IMAGE_FILE_BYTES_REVERSED_LO',         'The bytes of the word are reversed'),
                       ('IMAGE_FILE_32BIT_MACHINE',             'The computer supports 32-bit words'),
                       ('IMAGE_FILE_DEBUG_STRIPPED',            'Debugging information stripped'),
                       ('IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP',  'Image is on removable media, copy run from swap'),
                       ('IMAGE_FILE_NET_RUN_FROM_SWAP',         'Image is on network, copy run from swap'),
                       ('IMAGE_FILE_SYSTEM',                    'The image is a system file'),
                       ('IMAGE_FILE_DLL',                       'The image is a DLL file'),
                       ('IMAGE_FILE_UP_SYSTEM_ONLY',            'Uniprocessor computer only'),
                       ('IMAGE_FILE_BYTES_REVERSED_HI',         'The bytes of the word are reversed')]

_PE_DDLCharacteristics = [('RESERVED',                                      'Reserved'), 
                       ('RESERVED',                                         'Reserved'),
                       ('RESERVED',                                         'Reserved'),
                       ('RESERVED',                                         'Reserved'),
                       ('RESERVED',                                         'Reserved'),
                       ('RESERVED',                                         'Reserved'),
                       ('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE',           'Address space layout randomization'),
                       ('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY',        'Code integrity'),
                       ('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT',              'Data execution prevention (DEP)'),
                       ('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',            'Image isolation '),
                       ('IMAGE_DLLCHARACTERISTICS_NO_SEH',                  'Structured exception handling (SEH)'),
                       ('IMAGE_DLLCHARACTERISTICS_NO_BIND',                 'Do not bind the image)'),
                       ('RESERVED',                                         'Reserved'),
                       ('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',              'A WDM driver'),
                       ('RESERVED',                                         'Reserved'),
                       ('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE',   'Terminal server aware')]

_IMAGE_FILE_HEADER = [('Machine;',                 0x04,  ctypes.c_ushort,  '<H'),
                      ('NumberOfSections;',        0x06,  ctypes.c_ushort,  '<H'),
                      ('Time Date Stamp;',         0x08,  ctypes.c_uint32,  '<L'),
                      ('PointerToSymbolTable;',    0xc,   ctypes.c_uint32,  '<L'),
                      ('NumberOfSymbols;',         0x10,  ctypes.c_uint32,  '<L'),
                      ('SizeofOptionalHeader;',    0x14,  ctypes.c_ushort,  '<H'),
                      ('Characteristics;',         0x16,  ctypes.c_ushort,  '<H')]
         
_IMAGE_DOS_HEADER = [('e_magic',                    0x00,   ctypes.c_ushort, '<H'),
                     ('e_cblp',                     0x02,   ctypes.c_ushort, '<H'),
                     ('e_cp',                       0x04,   ctypes.c_ushort, '<H'),  
                     ('e_crlc',                     0x06,   ctypes.c_ushort, '<H'),
                     ('e_cparhdr',                  0x08,   ctypes.c_ushort, '<H'),
                     ('e_minalloc',                 0x0a,   ctypes.c_ushort, '<H'),
                     ('e_maxalloc',                 0x0c,   ctypes.c_ushort, '<H'),
                     ('e_ss',                       0x0e,   ctypes.c_ushort, '<H'),
                     ('e_sp',                       0x10,   ctypes.c_ushort, '<H'),
                     ('e_csum',                     0x12,   ctypes.c_ushort, '<H'),
                     ('e_ip',                       0x14,   ctypes.c_ushort, '<H'),
                     ('e_cs',                       0x16,   ctypes.c_ushort, '<H'),
                     ('e_lfarlc',                   0x18,   ctypes.c_ushort, '<H'),
                     ('e_ovno',                     0x1a,   ctypes.c_ushort, '<H'),
                     ('e_res[0]',                   0x1c,   ctypes.c_ushort, '<H'),
                     ('e_res[1]',                   0x1e,   ctypes.c_ushort, '<H'),
                     ('e_res[2]',                   0x20,   ctypes.c_ushort, '<H'),
                     ('e_res[3]',                   0x22,   ctypes.c_ushort, '<H'),
                     ('e_oemid',                    0x24,   ctypes.c_ushort, '<H'),
                     ('e_oeminfo',                  0x26,   ctypes.c_ushort, '<H'),
                     ('e_res2[0]',                  0x28,   ctypes.c_ushort, '<H'),
                     ('e_res2[1]',                  0x2a,   ctypes.c_ushort, '<H'),
                     ('e_res2[2]',                  0x2c,   ctypes.c_ushort, '<H'),
                     ('e_res2[3]',                  0x2e,   ctypes.c_ushort, '<H'),
                     ('e_res2[4]',                  0x30,   ctypes.c_ushort, '<H'),
                     ('e_res2[5]',                  0x32,   ctypes.c_ushort, '<H'),
                     ('e_res2[6]',                  0x34,   ctypes.c_ushort, '<H'),
                     ('e_res2[7]',                  0x36,   ctypes.c_ushort, '<H'),
                     ('e_res2[8]',                  0x38,   ctypes.c_ushort, '<H'),
                     ('e_res2[9]',                  0x3a,   ctypes.c_ushort, '<H'),
                     ('e_lfanew',                   0x3c,   ctypes.c_int32,  '<L')]

_IMAGE_OPTIONAL_HEADER = [('Magic;',                                                    0x00,   ctypes.c_ushort, '<H'),
                          ('MajorLinkerVersion;',                                       0x02,   ctypes.c_byte,   '<B'),
                          ('MinorLinkerVersion;',                                       0x03,   ctypes.c_byte,   '<B'),
                          ('SizeofCode;',                                               0x04,   ctypes.c_uint32, '<L'),
                          ('SizeOfInitializedData;',                                    0x08,   ctypes.c_uint32, '<L'),
                          ('SizeOfUninitializedData;',                                  0x0c,   ctypes.c_uint32, '<L'),
                          ('AddressOfEntryPoint;',                                      0x10,   ctypes.c_uint32, '<L'),
                          ('BaseOfCode;',                                               0x14,   ctypes.c_uint32, '<L'),
                          ('BaseOfDate;',                                               0x18,   ctypes.c_uint32, '<L'),
                          ('ImageBase;',                                                0x1c,   ctypes.c_uint32, '<L'),
                          ('SectionAlignment;',                                         0x20,   ctypes.c_uint32, '<L'),
                          ('FileAlignment;',                                            0x24,   ctypes.c_uint32, '<L'),
                          ('MajorOperatingSystemVersion;',                              0x28,   ctypes.c_ushort, '<H'),
                          ('MinorOperatingSystemVersion;',                              0x2a,   ctypes.c_ushort, '<H'),
                          ('MajorImageVersion;',                                        0x2c,   ctypes.c_ushort, '<H'),
                          ('MinorImageVersion;',                                        0x2e,   ctypes.c_ushort, '<H'),
                          ('MajorSubsystemVersion;',                                    0x30,   ctypes.c_ushort, '<H'),
                          ('MinorSubsystemVersion;',                                    0x32,   ctypes.c_ushort, '<H'),
                          ('Reserved1;',                                                0x34,   ctypes.c_uint32, '<L'),
                          ('SizeOfImage;',                                              0x38,   ctypes.c_uint32, '<L'),
                          ('SizeOfHeaders;',                                            0x3c,   ctypes.c_uint32, '<L'),
                          ('CheckSum;',                                                 0x40,   ctypes.c_uint32, '<L'),
                          ('Subsystem;',                                                0x44,   ctypes.c_ushort, '<H'),
                          ('DLLCharacteristics;',                                       0x46,   ctypes.c_ushort, '<H'),
                          ('SizeOfStackReserve;',                                       0x48,   ctypes.c_uint32, '<L'),
                          ('SizeOfStackCommit;',                                        0x4c,   ctypes.c_uint32, '<L'),
                          ('SizeOfHeapReserve;',                                        0x50,   ctypes.c_uint32, '<L'),
                          ('SizeOfHeapCommit;',                                         0x54,   ctypes.c_uint32, '<L'),
                          ('LoaderFlags;',                                              0x58,   ctypes.c_uint32, '<L'),
                          ('NumberOfRvaAndSizes;',                                      0x5c,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXPORT_TableVirtualAddress;',         0x60,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXPORT_Size;',                        0x64,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IMPORT_VirtualAddress;',              0x68,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IMPORT_Size;',                        0x6c,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESOURCE_TableVirtualAddress;',       0x70,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESOURCE_Size;',                      0x74,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXCEPTION_TableVirtualAddress;',      0x78,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXCEPTION_Size;',                     0x7c,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_SECURITY_TableVirtualAddress;',       0x80,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_SECURITY_Size;',                      0x84,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BASERELOC_TableVirtualAddress;',      0x88,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BASERELOC_Size;',                     0x8c,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DEBUG_TableVirtualAddress;',          0x90,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DEBUG_Size;',                         0x94,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT_TableVirtualAddress;',      0x98,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT_Size;',                     0x9c,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR_TableVirtualAddress;',      0xa0,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR_Size;',                     0xa4,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_TLS_TableVirtualAddress;',            0xa8,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_TLS_Size;',                           0xac,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TableVirtualAddress;',    0xb0,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_Size;',                   0xb4,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT_TableVirtualAddress;',   0xb8,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT_Size;',                  0xbc,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IAT_TableVirtualAddress;',            0xc0,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IAT_Size;',                           0xc4,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_TableVirtualAddress;',   0xc8,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_Size;',                  0xc8,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR_TableVirtualAddress;', 0xd0,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR_IAT_Size;',            0xd4,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESERVED;',                           0xd8,   ctypes.c_uint32, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESERVED;',                           0xdc,   ctypes.c_uint32, '<L')]

_SECTION_HEADER = [   ('Name;',                     0,   ctypes.c_byte,       '<BBBBBBBB'),
                      ('VirtualSize;',              8,   ctypes.c_uint32,     '<L'),
                      ('VirtualAddress;',           12,  ctypes.c_uint32,     '<L'),
                      ('SizeOfRawData;',            16,  ctypes.c_uint32,     '<L'),
                      ('PointerToRawData;',         20,  ctypes.c_uint32,     '<L'),
                      ('PointerToRelocations;',     24,  ctypes.c_uint32,     '<L'),
                      ('PointerToLinenumbers;',     28,  ctypes.c_uint32,     '<L'),
                      ('NumberOfRelocations;',      32,  ctypes.c_ushort,     '<H'),
                      ('NumberOfLinenumbers;',      34,  ctypes.c_ushort,     '<H'),
                      ('Characteristics;',          36,  ctypes.c_uint32,     '<L')]

_SECTION_FLAG = [('IMAGE_SCN_TYPE_DSECT'),
                 ('MAGE_SCN_TYPE_NOLOAD'),
                 ('IMAGE_SCN_TYPE_GROUP'),
                 ('IMAGE_SCN_TYPE_NO_PAD'),
                 ('IMAGE_SCN_TYPE_COPY'),
                 ('IMAGE_SCN_CNT_CODE'),
                 ('IMAGE_SCN_CNT_INITIALIZED_DATA'),
                 ('IMAGE_SCN_CNT_UNINITIALIZED_DATA'),
                 ('IMAGE_SCN_LNK_OTHER'),
                 ('IMAGE_SCN_LNK_INFO'),
                 ('IMAGE_SCN_TYPE_OVER'),
                 ('IMAGE_SCN_LNK_REMOVE'),
                 ('IMAGE_SCN_LNK_COMDAT'),
                 ('RESERVED'),
                 ('RESERVED'),
                 ('IMAGE_SCN_MEM_FARDATA'),
                 ('RESERVED'),
                 ('IMAGE_SCN_MEM_PURGEABLE'),
                 ('IMAGE_SCN_MEM_LOCKED'),
                 ('IMAGE_SCN_MEM_PRELOAD'),
                 
                 ('ALIGNMENTSECTION'),
                 ('ALIGNMENTSECTION'),
                 ('ALIGNMENTSECTION'),
                 ('ALIGNMENTSECTION'),
                 
                 ('IMAGE_SCN_LNK_NRELOC_OVFL'),
                 ('IMAGE_SCN_MEM_DISCARDABLE'),
                 ('IMAGE_SCN_MEM_NOT_CACHED'),
                 ('IMAGE_SCN_MEM_NOT_PAGED'),
                 ('IMAGE_SCN_MEM_SHARED'),
                 ('IMAGE_SCN_MEM_EXECUTE'),
                 ('IMAGE_SCN_MEM_READ'),
                 ('IMAGE_SCN_MEM_WRITE')]


_ELF_SECTION_HEADER = [('Magic Number;'             ,   0,   ctypes.c_uint32,       'L'),
                   ('Class'                         ,   4,   ctypes.c_byte,         'B'),
                   ('Endianess'                     ,   5,   ctypes.c_byte,         'B'),
                   ('Version'                       ,   6,   ctypes.c_byte,         'B'),
                   ('e_ident'                       ,   7,   ctypes.c_byte,         'B'),
                   ('ABI Version'                   ,   8,   ctypes.c_byte,         'B'),
                   ('e_type'                        ,   16,  ctypes.c_ushort,       'H'),
                   ('e_machine'                     ,   18,  ctypes.c_ushort,       'H'),
                   ('e_version'                     ,   20,  ctypes.c_uint32,       'L'),
                   ('Entry Point'                   ,   24,  ctypes.c_uint32,       'L'),
                   ('Entry Program Headers'         ,   28,  ctypes.c_uint32,       'L'),
                   ('Entry Section Header'          ,   32,  ctypes.c_uint32,       'L'),
                   ('Flags'                         ,   36,  ctypes.c_uint32,       'L'),
                   ('Size of this header'           ,   40,  ctypes.c_ushort,       'H'),
                   ('Size of program header'        ,   42,  ctypes.c_ushort,       'H'),
                   ('Number of program headers'     ,   44,  ctypes.c_ushort,       'H'),
                   ('Size of Section header'        ,   46,  ctypes.c_ushort,       'H'),
                   ('Number of section headers'     ,   48,  ctypes.c_ushort,       'H'),
                   ('Section header string table'   ,   50,  ctypes.c_ushort,       'H')]

_SECTION_HEADER_INFO = [('Class',       1,          'ELF 32 Bit'),
                        ('Class',       2,          'ELF 64 Bit'),
                        ('Endianess',   1,          'Little Endian'),
                        ('Endianess',   2,          'Big Endian'),
                        ('Version',     1,          'Original Version'),
                        ('e_ident',     0x00,       'System V'),
                        ('e_ident',     0x01,       'HP-UX'),
                        ('e_ident',     0x02,       'NetBSD'),
                        ('e_ident',     0x03,       'Linux'),
                        ('e_ident',     0x06,       'Solaris'),
                        ('e_ident',     0x07,       'AIX'),
                        ('e_ident',     0x08,       'IRIX'),
                        ('e_ident',     0x09,       'FreeBSD'),
                        ('e_ident',     0x0C,       'OpenBSD'),
                        ('e_type',      1,          'relocatable'),
                        ('e_type',      2,          'executable'),
                        ('e_type',      3,          'shared'),
                        ('e_type',      4,          'core'),
                        ('e_machine',   0x02,       'SPARC'),
                        ('e_machine',   0x03,       'x86'),
                        ('e_machine',   0x08,       'MIPS'),
                        ('e_machine',   0x14,       'PowerPC'),
                        ('e_machine',   0x28,       'ARM'),
                        ('e_machine',   0x2A,       'SuperH'),
                        ('e_machine',   0x32,       'IA-64'),
                        ('e_machine',   0x3E,       'x86-64'),
                        ('e_machine',   0xB7,       'AArch64'),
                        ('e_version',   1 ,         'Original Version')]

_ELF_PROGRAM_HEADER = [('Type;',                0,   ctypes.c_uint32,   'L'),
                       ('Offset;',              4,   ctypes.c_uint32,   'L'),
                       ('Virtual Addr;',        8,   ctypes.c_uint32,   'L'),
                       ('Physical Addr;',       12,  ctypes.c_uint32,   'L'),
                       ('FileSize;',            16,  ctypes.c_uint32,   'L'),
                       ('MemorySize;',          20,  ctypes.c_uint32,   'L'),
                       ('Flags;',               24,  ctypes.c_uint32,   'L'),
                       ('Alignment;',           28,  ctypes.c_uint32,   'L')]

_ELF_PROGRAMHEADER_TYPE = [(0,               'NULL'         ),
                           (1,               'LOAD'         ),
                           (2,               'DYNAMIC'      ),
                           (3,               'INTERP'       ),
                           (4,               'NOTE'         ),
                           (5,               'SHLTB'        ),
                           (6,               'PHDR'         ),
                           (7,               'TLS'          ),
                           (1879048192,      'LORPOC'       ),
                           (2147483647,      'HIPROC'       ),
                           (1685382480,      'GNU_EH_FRAME' ),
                           (1685382481,      'GNU_STACK'    )]


_ELF_SECTIONHEADER = [ ('Name;',                0,   ctypes.c_uint32,   'L'),
                       ('Type;',                4,   ctypes.c_uint32,   'L'),
                       ('Flags;',               8,   ctypes.c_uint32,   'L'),
                       ('Virtual Addr;',        12,  ctypes.c_uint32,   'L'),
                       ('Offset;',              16,  ctypes.c_uint32,   'L'),
                       ('Size;',                20,  ctypes.c_uint32,   'L'),
                       ('Link;',                24,  ctypes.c_uint32,   'L'),
                       ('Info;',                28,  ctypes.c_uint32,   'L'),
                       ('Addralign;',           24,  ctypes.c_uint32,   'L'),
                       ('Entsize;',             24,  ctypes.c_uint32,   'L'),]


_ELF_SECTION_HEADER_TYPE = [('NULL',    0),
                            ('PROGBITS',1),
                            ('SYMTAB',  2),
                            ('STRTAB',  3),
                            ('RELA',    4),
                            ('HASH',    5),
                            ('DYNAMIC', 6),
                            ('NOTE',    7),
                            ('NOBITS',  8),
                            ('REL',     9),
                            ('SHLIB',   0xa),
                            ('DYNSYM',  0xb),
                            ('LOPROC',  0x70000000),
                            ('HIPROC',  0x7fffffff),
                            ('LOUSER',  0x80000000),
                            ('HIUSER',  0xffffffff),
                            ('VERSYM',  0x6fffffff),
                            ('VERNEED', 0x6ffffffe)]
