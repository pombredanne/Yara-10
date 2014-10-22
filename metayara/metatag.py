TAGS = { '0x14c': ('IMAGE_FILE_MACHINE_I386'),
         '0x0200': ('IMAGE_FILE_MACHINE_IA64'),
         '0x8664': ('IMAGE_FILE_MACHINE_AMD64')}

_IMAGE_FILE_HEADER = [('Machine;',                 0x04,  0x02, '<H'),
                      ('NumberOfSections;',        0x06,  0x02, '<H'),
                      ('Time Date Stamp;',         0x08,  0x04, '<L'),
                      ('PointerToSymbolTable;',    0xc,   0x04, '<L'),
                      ('NumberOfSymbols;',         0x10,  0x04, '<L'),
                      ('SizeofOptionalHeader;',    0x14,  0x02, '<H'),
                      ('Characteristics;',         0x16,  0x02, '<H')]
 
_IMAGE_DOS_HEADER = [('e_magic',                    0x00,   0x02, '<H'),
                     ('e_cblp',                     0x02,   0x02, '<H'),
                     ('e_cp',                       0x04,   0x02, '<H'),  
                     ('e_crlc',                     0x06,   0x02, '<H'),
                     ('e_cparhdr',                  0x08,   0x02, '<H'),
                     ('e_minalloc',                 0x0a,   0x02, '<H'),
                     ('e_maxalloc',                 0x0c,   0x02, '<H'),
                     ('e_ss',                       0x0e,   0x02, '<H'),
                     ('e_sp',                       0x10,   0x02, '<H'),
                     ('e_csum',                     0x12,   0x02, '<H'),
                     ('e_ip',                       0x14,   0x02, '<H'),
                     ('e_cs',                       0x16,   0x02, '<H'),
                     ('e_lfarlc',                   0x18,   0x02, '<H'),
                     ('e_ovno',                     0x1a,   0x02, '<H'),
                     ('e_res[0]',                   0x1c,   0x02, '<H'),
                     ('e_res[1]',                   0x1e,   0x02, '<H'),
                     ('e_res[2]',                   0x20,   0x02, '<H'),
                     ('e_res[3]',                   0x22,   0x02, '<H'),
                     ('e_oemid',                    0x24,   0x02, '<H'),
                     ('e_oeminfo',                  0x26,   0x02, '<H'),
                     ('e_res2[0]',                  0x28,   0x02, '<H'),
                     ('e_res2[1]',                  0x2a,   0x02, '<H'),
                     ('e_res2[2]',                  0x2c,   0x02, '<H'),
                     ('e_res2[3]',                  0x2e,   0x02, '<H'),
                     ('e_res2[4]',                  0x30,   0x02, '<H'),
                     ('e_res2[5]',                  0x32,   0x02, '<H'),
                     ('e_res2[6]',                  0x34,   0x02, '<H'),
                     ('e_res2[7]',                  0x36,   0x02, '<H'),
                     ('e_res2[8]',                  0x38,   0x02, '<H'),
                     ('e_res2[9]',                  0x3a,   0x02, '<H'),
                     ('e_lfanew',                   0x3c,   0x04, '<L'),]           

_IMAGE_OPTIONAL_HEADER = [('Magic;',                                                    0x00,   0x02, '<H'),
                          ('MajorLinkerVersion;',                                       0x02,   0x01, '<B'),
                          ('MinorLinkerVersion;',                                       0x03,   0x01, '<B'),
                          ('SizeofCode;',                                               0x04,   0x04, '<L'),
                          ('SizeOfInitializedData;',                                    0x08,   0x04, '<L'),
                          ('SizeOfUninitializedData;',                                  0x0c,   0x04, '<L'),
                          ('AddressOfEntryPoint;',                                      0x10,   0x04, '<L'),
                          ('BaseOfCode;',                                               0x14,   0x04, '<L'),
                          ('BaseOfDate;',                                               0x18,   0x04, '<L'),
                          ('ImageBase;',                                                0x1c,   0x04, '<L'),
                          ('SectionAlignment;',                                         0x20,   0x04, '<L'),
                          ('FileAlignment;',                                            0x24,   0x04, '<L'),
                          ('MajorOperatingSystemVersion;',                              0x28,   0x02, '<H'),
                          ('MinorOperatingSystemVersion;',                              0x2a,   0x02, '<H'),
                          ('MajorImageVersion;',                                        0x2c,   0x02, '<H'),
                          ('MinorImageVersion;',                                        0x2e,   0x02, '<H'),
                          ('MajorSubsystemVersion;',                                    0x30,   0x02, '<H'),
                          ('MinorSubsystemVersion;',                                    0x32,   0x02, '<H'),
                          ('Reserved1;',                                                0x34,   0x04, '<L'),
                          ('SizeOfImage;',                                              0x38,   0x04, '<L'),
                          ('SizeOfHeaders;',                                            0x3c,   0x04, '<L'),
                          ('CheckSum;',                                                 0x40,   0x04, '<L'),
                          ('Subsystem;',                                                0x44,   0x02, '<H'),
                          ('DLLCharacteristics;',                                       0x46,   0x02, '<H'),
                          ('SizeOfStackReserve;',                                       0x48,   0x04, '<L'),
                          ('SizeOfStackCommit;',                                        0x4c,   0x04, '<L'),
                          ('SizeOfHeapReserve;',                                        0x50,   0x04, '<L'),
                          ('SizeOfHeapCommit;',                                         0x54,   0x04, '<L'),
                          ('LoaderFlags;',                                              0x58,   0x04, '<L'),
                          ('NumberOfRvaAndSizes;',                                      0x5c,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXPORT_TableVirtualAddress;',         0x60,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXPORT_Size;',                        0x64,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IMPORT_VirtualAddress;',              0x68,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IMPORT_Size;',                        0x6c,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESOURCE_TableVirtualAddress;',       0x70,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESOURCE_Size;',                      0x74,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXCEPTION_TableVirtualAddress;',      0x78,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_EXCEPTION_Size;',                     0x7c,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_SECURITY_TableVirtualAddress;',       0x80,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_SECURITY_Size;',                      0x84,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BASERELOC_TableVirtualAddress;',      0x88,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BASERELOC_Size;',                     0x8c,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DEBUG_TableVirtualAddress;',          0x90,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DEBUG_Size;',                         0x94,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT_TableVirtualAddress;',      0x98,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT_Size;',                     0x9c,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR_TableVirtualAddress;',      0xa0,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR_Size;',                     0xa4,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_TLS_TableVirtualAddress;',            0xa8,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_TLS_Size;',                           0xac,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TableVirtualAddress;',    0xb0,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_Size;',                   0xb4,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT_TableVirtualAddress;',   0xb8,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT_Size;',                  0xbc,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IAT_TableVirtualAddress;',            0xc0,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_IAT_Size;',                           0xc4,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_TableVirtualAddress;',   0xc8,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_Size;',                  0xc8,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR_TableVirtualAddress;', 0xd0,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR_IAT_Size;',            0xd4,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESERVED;',                           0xd8,   0x04, '<L'),
                          ('IMAGE_DIRECTORY_ENTRY_RESERVED;',                           0xdc,   0x04, '<L')]
