TAGS = { '0x14c': ('IMAGE_FILE_MACHINE_I386'),
         '0x0200': ('IMAGE_FILE_MACHINE_IA64'),
         '0x8664': ('IMAGE_FILE_MACHINE_AMD64')}

_IMAGE_FILE_HEADER = [('Machine',                 4,  2, '<H'),
                      ('NumberOfSections',        6,  2, '<H'),
                      ('Time Date Stamp',         8,  4, '<L'),
                      ('PointerToSymbolTable',    12, 4, '<L'),
                      ('NumberOfSymbols',         16, 4, '<L'),
                      ('SizeofOptionalHeader',    20, 2, '<H'),
                      ('Characteristics',         22, 2, '<H')]
            
_IMAGE_OPTIONAL_HEADER = [('Magic;',                        0,   2, '<H'),
                          ('MajorLinkerVersion;',           2,   1, '<B'),
                          ('MinorLinkerVersion;',           3,   1, '<B'),
                          ('SizeofCode;',                   4,   4, '<L'),
                          ('SizeOfInitializedData;',        8,   4, '<L'),
                          ('SizeOfUninitializedData;',      12,  4, '<L'),
                          ('AddressOfEntryPoint;',          16,  4, '<L'),
                          ('BaseOfCode;',                   20,  4, '<L'),
                          ('BaseOfDate;',                   24,  4, '<L'),
                          ('ImageBase;',                    28,  4, '<L'),
                          ('SectionAlignment;',             32,  4, '<L'),
                          ('FileAlignment;',                36,  4, '<L'),
                          ('MajorOperatingSystemVersion;',  36,  2, '<H'),
                          ('MinorOperatingSystemVersion;',  38,  2, '<H'),
                          ('MajorImageVersion;',            40,  2, '<H'),
                          ('MinorImageVersion;',            42,  2, '<H'),
                          ('MajorSubsystemVersion;',        44,  2, '<H'),
                          ('MinorSubsystemVersion;',        46,  2, '<H'),
                          ('Reserved1;',                    48,  4, '<L'), #Dafuq happens here skipping 8 bits
                          ('SizeOfImage;',                  56,  4, '<L'),
                          ('SizeOfHeaders;',                60,  4, '<L'),
                          ('CheckSum;',                     64,  4, '<L'),
                          ('Subsystem;',                    68,  2, '<H'),
                          ('DLLCharacteristics;',           70,  2, '<H'),
                          ('SizeOfStackReserve;',          72,  4, '<L'),
                          ('SizeOfStackCommit;',            76,  4, '<L'),
                          ('SizeOfHeapReserve;',            80,  4, '<L'),
                          ('SizeOfHeapCommit;',             84,  4, '<L'),
                          ('LoaderFlags;',                  88,  4, '<L'),
                          ('NumberOfRvaAndSizes;',          92,  4, '<L'),]