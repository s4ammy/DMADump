#include "pe_header.h"

// ----------------------------------------------------------------
// Shared initializer called by both constructors
// ----------------------------------------------------------------
void pe_header::_init(PD_OPTIONS* options, stream_wrapper* stream, void* base)
{
    _options       = options;
    _stream        = stream;
    _original_base = base;

    _image_size           = 0;
    _raw_header_size      = 0;
    _disk_image_size      = 0;
    _unique_hash          = 0;
    _unique_hash_ep       = 0;
    _unique_hash_ep_short = 0;
    _correction_offset    = 0;

    _header_dos              = nullptr;
    _header_pe32             = nullptr;
    _header_pe64             = nullptr;
    _header_export_directory = nullptr;
    _export_list             = nullptr;

    _header_import_descriptors_count = 0;
    _header_import_descriptors       = nullptr;
    _header_sections                 = nullptr;
    _header_section_sizes            = nullptr;

    _name_filepath_long_size     = 0;
    _name_filepath_long          = nullptr;
    _name_filepath_short_size    = 0;
    _name_filepath_short         = nullptr;
    _name_original_exports_size  = 0;
    _name_original_exports       = nullptr;
    _name_original_manifest_size = 0;
    _name_original_manifest      = nullptr;
    _name_symbols_path_size      = 0;
    _name_symbols_path           = nullptr;

    _parsed_dos      = false;
    _parsed_pe_32    = false;
    _parsed_pe_64    = false;
    _parsed_sections = false;

    _image       = nullptr;
    _raw_header  = nullptr;
    _disk_image  = nullptr;

    if (_stream != nullptr)
    {
        _name_filepath_long = new char[FILEPATH_SIZE];
        _name_filepath_long_size = _stream->get_long_name(_name_filepath_long, FILEPATH_SIZE);
        _name_filepath_short = new char[FILEPATH_SIZE];
        _name_filepath_short_size = _stream->get_short_name(_name_filepath_short, FILEPATH_SIZE);
    }

    if (_options->Verbose)
        fprintf(stdout, "INFO: Initialized header for module name %s.\n", get_name());
}

// ----------------------------------------------------------------
// File-based constructor (used by pe_hash_database)
// ----------------------------------------------------------------
pe_header::pe_header(char* filename, PD_OPTIONS* options)
{
    _init(options, (stream_wrapper*) new file_stream(filename), nullptr);
}

// ----------------------------------------------------------------
// DMA constructor — stream already created by caller; pe_header owns it
// ----------------------------------------------------------------
pe_header::pe_header(stream_wrapper* stream, dma_module_list* modules, PD_OPTIONS* options)
{
    void* base = (void*) stream->get_address();
    _init(options, stream, base);
}

// ----------------------------------------------------------------
// Stubs for methods declared in header but not in reference impl
// ----------------------------------------------------------------
bool pe_header::process_relocation_directory()
{
    return false;
}

__int64 pe_header::get_export_addresses()
{
    return 0;
}

// ----------------------------------------------------------------
// Everything below is identical to the reference pe_header.cpp
// ----------------------------------------------------------------

export_list* pe_header::get_exports()
{
    if ((_parsed_pe_32 || _parsed_pe_64) && _export_list != nullptr)
        return _export_list;
    return nullptr;
}

void pe_header::print_report(FILE* stream)
{
}

bool pe_header::somewhat_parsed()
{
    return _parsed_pe_32 || _parsed_pe_64;
}

bool pe_header::is_dll()
{
    if (_parsed_pe_32)
        return (_header_pe32->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    if (_parsed_pe_64)
        return (_header_pe64->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    return false;
}

bool pe_header::is_exe()
{
    if (_parsed_pe_32)
        return !(_header_pe32->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
               !(_header_pe32->FileHeader.Characteristics & IMAGE_FILE_SYSTEM);
    if (_parsed_pe_64)
        return !(_header_pe64->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
               !(_header_pe64->FileHeader.Characteristics & IMAGE_FILE_SYSTEM);
    return false;
}

bool pe_header::is_sys()
{
    if (_parsed_pe_32)
        return (_header_pe32->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0;
    if (_parsed_pe_64)
        return (_header_pe64->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0;
    return false;
}

bool pe_header::is_64()
{
    return _parsed_pe_64;
}

void pe_header::set_name(char* new_name)
{
    if (_name_filepath_short != nullptr)
        delete[] _name_filepath_short;
    _name_filepath_short = new char[strlen(new_name) + 1];
    strcpy_s(_name_filepath_short, strlen(new_name) + 1, new_name);
    _name_filepath_short_size = strlen(_name_filepath_short);
}

char* pe_header::get_name()
{
    if (_name_filepath_short_size > 0 && _name_filepath_short != nullptr)
        return _name_filepath_short;
    return (char*)"hiddenmodule";
}

unsigned __int64 pe_header::get_virtual_size()
{
    if (_parsed_pe_32 || _parsed_pe_64)
        return _image_size;
    return 0;
}

bool pe_header::process_hash()
{
    _unique_hash = 0;
    if (_parsed_pe_32 || _parsed_pe_64)
    {
        SIZE_T offset    = 0;
        SIZE_T read_size = 0;
        if (_parsed_pe_32)
        {
            offset    = _header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            read_size = 4;
        }
        else
        {
            offset    = _header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            read_size = 8;
        }

        unsigned __int64 last_dw = (unsigned __int64)-1;
        bool more;
        do
        {
            more = false;
            if (_test_read(_image, _image_size, _image + offset, read_size))
            {
                unsigned __int64 new_dw;
                if (read_size == 4)
                    new_dw = *((DWORD*) (_image + (long) offset));
                else
                    new_dw = *((unsigned __int64*) (_image + (long) offset));

                if (new_dw == 0 && last_dw == 0)
                    break;
                if (new_dw == 0)
                {
                    _unique_hash = _unique_hash ^ 0x8ADFA91F8ADFA91F;
                    _unique_hash = _rotl64(_unique_hash, 0x13);
                }
                else
                {
                    _unique_hash = _unique_hash ^ 0x18F31A228FA9B17A;
                    _unique_hash = _rotl64(_unique_hash, 0x17);
                }
                offset += read_size;
                last_dw = new_dw;
                more = true;
            }
        } while (more);

        if (_parsed_sections)
        {
            for (int i = 0; i < _num_sections; i++)
            {
                _unique_hash = _unique_hash ^ *((unsigned __int64*) (&_header_sections[i].Name));
                _unique_hash = _rotl64(_unique_hash, 0x21);
                _unique_hash = _unique_hash ^ _header_sections[i].SizeOfRawData;
                _unique_hash = _rotl64(_unique_hash, 0x13);
                _unique_hash = _unique_hash ^ _header_sections[i].Characteristics;
                _unique_hash = _rotl64(_unique_hash, 0x17);
            }
        }
        return true;
    }
    return false;
}

unsigned __int64 pe_header::_hash_short_asm(SIZE_T offset)
{
    unsigned __int64 result = 0;

    if (offset == 0 || !_options->EntryPointHash)
        return result;

    if (_test_read(_image, _image_size, _image + offset, 8))
    {
        result = *((unsigned __int64*) (_image + offset));
        if (((result ^ (result << 8)) & 0xffffffffffffff00) == 0)
            return 0;
    }
    return result;
}

unsigned __int64 pe_header::_hash_asm(SIZE_T offset)
{
    unsigned __int64 result = 0;

    if (offset == 0 || !_options->EntryPointHash)
        return result;

    if (_parsed_pe_32 || _parsed_pe_64)
    {
        NMD_X86_MODE mode = _parsed_pe_32 ? NMD_X86_MODE_32 : NMD_X86_MODE_64;

        bool more;
        bool return_hit = false;
        NMD_X86Instruction inst;
        int inst_count = 0;
        do
        {
            more = false;
            if (_test_read(_image, _image_size, _image + offset, 20))
            {
                more = true;
                if (nmd_x86_decode_buffer(_image + offset, 20, &inst, mode, NMD_X86_DECODER_FLAGS_MINIMAL))
                {
                    result = (result + inst.opcode + (inst.opcode << 8) + (inst.opcode << 16) + (inst.opcode << 24)) ^ 0x8ADFA91F8ADFA91F;
                    result = _rotl64(result, 0x13);
                    result = (result + inst.prefixes + (inst.prefixes << 16)) ^ 0x18F31A228FA9B17A;
                    result = _rotl64(result, 0x17);
                    if (inst.group == NMD_GROUP_RET)
                        return_hit = true;
                    offset += inst.length;
                }
                else
                {
                    result = result ^ 0xCDA13B89DB31AF13;
                    result = _rotl64(result, 0x18);
                    offset++;
                }
                inst_count++;
            }
            if (more)
            {
                if (return_hit && inst_count >= EP_HASH_OPCODES_MIN)
                    more = false;
                if (inst_count >= EP_HASH_OPCODES_MAX)
                    more = false;
            }
        } while (more);

        if (inst_count >= EP_HASH_OPCODES_MIN)
            return result;
    }
    return 0;
}

bool pe_header::process_hash_ep()
{
    _unique_hash_ep       = 0;
    _unique_hash_ep_short = 0;

    if (_parsed_pe_32 || _parsed_pe_64)
    {
        SIZE_T offset = 0;
        if (_parsed_pe_32)
            offset = _header_pe32->OptionalHeader.AddressOfEntryPoint;
        else
            offset = _header_pe64->OptionalHeader.AddressOfEntryPoint;

        unsigned __int64 hash = _hash_short_asm(offset);
        if (hash != 0)
        {
            _unique_hash_ep_short = hash;
            hash = _hash_asm(offset);
            if (hash != 0)
            {
                _unique_hash_ep = hash;
                return true;
            }
        }
    }
    return false;
}

bool pe_header::write_image(char* filename)
{
    if (_disk_image_size > 0)
    {
        FILE* fh = fopen(filename, "wb");
        if (fh != nullptr)
        {
            fwrite(_disk_image, 1, _disk_image_size, fh);
            fclose(fh);
        }
    }
    return false;
}

IMPORT_SUMMARY pe_header::get_imports_information(export_list* exports)
{
    return get_imports_information(exports, _image_size);
}

IMPORT_SUMMARY pe_header::get_imports_information(export_list* exports, __int64 size_limit)
{
    unordered_set<unsigned __int64> import_addresses;

    if (_options->Verbose)
        printf("INFO: Building import information.\n");

    IMPORT_SUMMARY result;
    result.COUNT_UNIQUE_IMPORT_ADDRESSES = 0;
    result.COUNT_UNIQUE_IMPORT_LIBRARIES = 0;
    result.HASH_GENERIC  = 0;
    result.HASH_SPECIFIC = 0;

    size_t hash_generic  = 0x1a78ac10;
    size_t hash_specific = 0x1a78ac10;
    hash<string> hasher;

    if (_parsed_sections)
    {
        unsigned __int32 cand32_last = 0;
        unsigned __int64 cand64_last = 0;
        for (__int64 offset = 0; offset < _image_size - 8 && offset < size_limit - 8; offset += 4)
        {
            unsigned __int32 cand32 = *((__int32*) (_image + offset));
            if (cand32 != cand32_last)
            {
                if (exports->contains(cand32))
                {
                    export_entry entry = exports->find(cand32);
                    auto got = import_addresses.find(cand32);
                    if (got == import_addresses.end())
                    {
                        import_addresses.insert(cand32);
                        result.COUNT_UNIQUE_IMPORT_ADDRESSES++;
                        if (entry.name != nullptr)
                        {
                            hash_generic  = hash_generic  ^ hasher(string(entry.name));
                            hash_specific = hash_specific ^ hasher(string(entry.name));
                        }
                        if (entry.library_name != nullptr)
                        {
                            hash_generic  = hash_generic  ^ (hasher(string(entry.library_name)) << 1);
                            hash_specific = hash_specific ^ (hasher(string(entry.library_name)) << 1);
                        }
                        hash_generic  = _rotl(hash_generic, 0x05);
                        hash_specific = hash_specific ^ (size_t) offset;
                        hash_specific = _rotl(hash_specific, 0x05);
                    }
                }
            }
            cand32_last = cand32;

            unsigned __int64 cand64 = *((unsigned __int64*) (_image + offset));
            if (cand64 != cand64_last && cand64 > 0xffffffff)
            {
                if (exports->contains(cand64))
                {
                    export_entry entry = exports->find(cand64);
                    auto got = import_addresses.find(cand64);
                    if (got == import_addresses.end())
                    {
                        import_addresses.insert(cand64);
                        result.COUNT_UNIQUE_IMPORT_ADDRESSES++;
                        if (entry.name != nullptr)
                        {
                            hash_generic  = hash_generic  ^ hasher(string(entry.name));
                            hash_specific = hash_specific ^ hasher(string(entry.name));
                        }
                        if (entry.library_name != nullptr)
                        {
                            hash_generic  = hash_generic  ^ (hasher(string(entry.library_name)) << 1);
                            hash_specific = hash_specific ^ (hasher(string(entry.library_name)) << 1);
                        }
                        hash_generic  = _rotl(hash_generic, 0x05);
                        hash_specific = hash_specific ^ (size_t) offset;
                        hash_specific = _rotl(hash_specific, 0x05);
                    }
                }
            }
            cand64_last = cand64;
        }
    }

    result.HASH_GENERIC  = hash_generic;
    result.HASH_SPECIFIC = hash_specific;

    if (_options->Verbose)
    {
        printf("INFO: Finished building import information:\n");
        printf("INFO: Count Unique Import Addresses = %i\n", (int) result.COUNT_UNIQUE_IMPORT_ADDRESSES);
        printf("INFO: Count Unique Import Libraries = %i\n", (int) result.COUNT_UNIQUE_IMPORT_LIBRARIES);
        printf("INFO: Generic Hash = 0x%llX\n",  result.HASH_GENERIC);
        printf("INFO: Specific Hash = 0x%llX\n", result.HASH_SPECIFIC);
    }
    return result;
}

unsigned __int64 pe_header::get_hash()
{
    if (_unique_hash == 0)
        process_hash();
    return _unique_hash;
}

unsigned __int64 pe_header::get_hash_ep()
{
    if (_unique_hash_ep == 0)
        process_hash_ep();
    return _unique_hash_ep;
}

unsigned __int64 pe_header::get_hash_ep_short()
{
    if (_unique_hash_ep_short == 0)
        process_hash_ep();
    return _unique_hash_ep_short;
}

bool pe_header::build_pe_header(__int64 size, bool amd64)
{
    return build_pe_header(size, amd64, 99);
}

bool pe_header::build_pe_header(__int64 size, bool amd64, int num_sections_limit)
{
    if (_stream != nullptr)
    {
        _raw_header_size = 0x2000;
        _raw_header = new unsigned char[_raw_header_size];
        memset(_raw_header, 0, _raw_header_size);
        _original_base = (void*) ((__int64) _original_base - (__int64) _raw_header_size);
        _stream->update_base(-(__int64) _raw_header_size);

        _header_dos = (IMAGE_DOS_HEADER*) _raw_header;
        _header_dos->e_magic    = 0x5a4d;
        _header_dos->e_cblp     = 0x0090;
        _header_dos->e_cp       = 0x0003;
        _header_dos->e_crlc     = 0x0000;
        _header_dos->e_cparhdr  = 0x0004;
        _header_dos->e_minalloc = 0x0000;
        _header_dos->e_maxalloc = 0xffff;
        _header_dos->e_ss       = 0x0000;
        _header_dos->e_sp       = 0x00b8;
        _header_dos->e_csum     = 0x0000;
        _header_dos->e_ip       = 0x0000;
        _header_dos->e_cs       = 0x0000;
        _header_dos->e_lfarlc   = 0x0040;
        _header_dos->e_ovno     = 0x0000;
        memset(&_header_dos->e_res,  0, sizeof(WORD) * 4);
        _header_dos->e_oemid    = 0x0000;
        _header_dos->e_oeminfo  = 0x0000;
        memset(&_header_dos->e_res2, 0, sizeof(WORD) * 10);
        _header_dos->e_lfanew   = 0x000000e0;

        _parsed_dos = true;

        unsigned char* base_pe = _header_dos->e_lfanew + _raw_header;

        if (!amd64)
        {
            _header_pe32 = (IMAGE_NT_HEADERS32*) base_pe;
            _header_pe32->Signature = 0x00004550;
            _header_pe32->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
            _header_pe32->FileHeader.NumberOfSections = 1;
            _header_pe32->FileHeader.NumberOfSymbols = 0;
            _header_pe32->FileHeader.PointerToSymbolTable = 0;
            _header_pe32->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
            if (_options->ReconstructHeaderAsDll)
                _header_pe32->FileHeader.Characteristics = 0x0002;
            else
                _header_pe32->FileHeader.Characteristics = 0x2000;
            _header_pe32->OptionalHeader.Magic = 0x10b;
            _header_pe32->OptionalHeader.MajorLinkerVersion = 0x08;
            _header_pe32->OptionalHeader.MinorLinkerVersion = 0x00;
            _header_pe32->OptionalHeader.SizeOfCode = 0x00000000;
            _header_pe32->OptionalHeader.SizeOfInitializedData = 0x00000000;
            _header_pe32->OptionalHeader.SizeOfUninitializedData = 0x00000000;
            _header_pe32->OptionalHeader.AddressOfEntryPoint = 0x2000;
            _header_pe32->OptionalHeader.BaseOfCode = 0x00002000;
            _header_pe32->OptionalHeader.ImageBase = (DWORD) _original_base;
            _header_pe32->OptionalHeader.SectionAlignment = 0x00001000;
            _header_pe32->OptionalHeader.FileAlignment = 0x000001000;
            _header_pe32->OptionalHeader.MajorOperatingSystemVersion = 0x0004;
            _header_pe32->OptionalHeader.MinorOperatingSystemVersion = 0x0000;
            _header_pe32->OptionalHeader.MajorImageVersion = 0x0000;
            _header_pe32->OptionalHeader.MinorImageVersion = 0x0000;
            _header_pe32->OptionalHeader.MajorSubsystemVersion = 0x0005;
            _header_pe32->OptionalHeader.MinorSubsystemVersion = 0x0002;
            _header_pe32->OptionalHeader.Win32VersionValue = 0x00000000;
            _header_pe32->OptionalHeader.SizeOfImage = 0x00006000;
            _header_pe32->OptionalHeader.SizeOfHeaders = 0x00002000;
            _header_pe32->OptionalHeader.CheckSum = 0x00000000;
            _header_pe32->OptionalHeader.Subsystem = 0x0003;
            _header_pe32->OptionalHeader.DllCharacteristics = 0x0000;
            _header_pe32->OptionalHeader.SizeOfStackReserve = 0x0000000000100000;
            _header_pe32->OptionalHeader.SizeOfStackCommit  = 0x0000000000001000;
            _header_pe32->OptionalHeader.SizeOfHeapReserve  = 0x0000000000100000;
            _header_pe32->OptionalHeader.SizeOfHeapCommit   = 0x0000000000001000;
            _header_pe32->OptionalHeader.LoaderFlags = 0x00000000;
            _header_pe32->OptionalHeader.NumberOfRvaAndSizes = 0x00000010;
            memset(&_header_pe32->OptionalHeader.DataDirectory, 0, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

            _header_sections = (IMAGE_SECTION_HEADER*) (base_pe + sizeof(IMAGE_NT_HEADERS32));
            _parsed_pe_32 = true;
        }
        else
        {
            _header_pe64 = (IMAGE_NT_HEADERS64*) base_pe;
            _header_pe64->Signature = 0x00004550;
            _header_pe64->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
            _header_pe64->FileHeader.NumberOfSections = 1;
            _header_pe64->FileHeader.NumberOfSymbols = 0;
            _header_pe64->FileHeader.PointerToSymbolTable = 0;
            _header_pe64->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
            if (_options->ReconstructHeaderAsDll)
                _header_pe64->FileHeader.Characteristics = 0x0002;
            else
                _header_pe64->FileHeader.Characteristics = 0x2000;
            _header_pe64->OptionalHeader.Magic = 0x020b;
            _header_pe64->OptionalHeader.MajorLinkerVersion = 0x08;
            _header_pe64->OptionalHeader.MinorLinkerVersion = 0x00;
            _header_pe64->OptionalHeader.SizeOfCode = 0x00000000;
            _header_pe64->OptionalHeader.SizeOfInitializedData = 0x00000000;
            _header_pe64->OptionalHeader.SizeOfUninitializedData = 0x00000000;
            _header_pe64->OptionalHeader.AddressOfEntryPoint = 0x2000;
            _header_pe64->OptionalHeader.BaseOfCode = 0x00002000;
            _header_pe64->OptionalHeader.ImageBase = (__int64) _original_base;
            _header_pe64->OptionalHeader.SectionAlignment = 0x00001000;
            _header_pe64->OptionalHeader.FileAlignment = 0x000001000;
            _header_pe64->OptionalHeader.MajorOperatingSystemVersion = 0x0004;
            _header_pe64->OptionalHeader.MinorOperatingSystemVersion = 0x0000;
            _header_pe64->OptionalHeader.MajorImageVersion = 0x0000;
            _header_pe64->OptionalHeader.MinorImageVersion = 0x0000;
            _header_pe64->OptionalHeader.MajorSubsystemVersion = 0x0005;
            _header_pe64->OptionalHeader.MinorSubsystemVersion = 0x0002;
            _header_pe64->OptionalHeader.Win32VersionValue = 0x00000000;
            _header_pe64->OptionalHeader.SizeOfImage = 0x00006000;
            _header_pe64->OptionalHeader.SizeOfHeaders = 0x00002000;
            _header_pe64->OptionalHeader.CheckSum = 0x00000000;
            _header_pe64->OptionalHeader.Subsystem = 0x0003;
            _header_pe64->OptionalHeader.DllCharacteristics = 0x0000;
            _header_pe64->OptionalHeader.SizeOfStackReserve = 0x0000000000100000;
            _header_pe64->OptionalHeader.SizeOfStackCommit  = 0x0000000000001000;
            _header_pe64->OptionalHeader.SizeOfHeapReserve  = 0x0000000000100000;
            _header_pe64->OptionalHeader.SizeOfHeapCommit   = 0x0000000000001000;
            _header_pe64->OptionalHeader.LoaderFlags = 0x00000000;
            _header_pe64->OptionalHeader.NumberOfRvaAndSizes = 0x00000010;
            memset(&_header_pe64->OptionalHeader.DataDirectory, 0, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

            _header_sections = (IMAGE_SECTION_HEADER*) (base_pe + sizeof(IMAGE_NT_HEADERS64));
            _parsed_pe_64 = true;
        }

        _num_sections  = 0;
        __int64 image_size = _raw_header_size;
        while (_stream->estimate_section_size((long) image_size) != 0 &&
               image_size >= size &&
               _num_sections < 99 && _num_sections < num_sections_limit)
        {
            __int64 est_size = _stream->estimate_section_size((long) image_size);

            _header_sections[_num_sections].PointerToRawData         = (DWORD) image_size;
            _header_sections[_num_sections].SizeOfRawData            = (DWORD) est_size;
            _header_sections[_num_sections].VirtualAddress           = (DWORD) image_size;
            _header_sections[_num_sections].Misc.PhysicalAddress     = (DWORD) image_size;
            _header_sections[_num_sections].Misc.VirtualSize         = (DWORD) est_size;
            _header_sections[_num_sections].Characteristics          = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
            char name[9];
            sprintf_s(name, 9, "pd_rec%i", _num_sections);
            memcpy(&_header_sections[_num_sections].Name, name, 8);
            _header_sections[_num_sections].NumberOfLinenumbers  = 0;
            _header_sections[_num_sections].NumberOfRelocations  = 0;
            _header_sections[_num_sections].PointerToLinenumbers = 0;

            if (_options->Verbose)
                printf("%s: size %x\n", name, (unsigned) image_size);

            _num_sections++;
            image_size += est_size;
        }

        if (!amd64)
        {
            _header_pe32->FileHeader.NumberOfSections   = _num_sections;
            _header_pe32->OptionalHeader.SizeOfImage    = (DWORD) image_size;
        }
        else
        {
            _header_pe64->FileHeader.NumberOfSections   = _num_sections;
            _header_pe64->OptionalHeader.SizeOfImage    = (DWORD) image_size;
        }
        return true;
    }
    return false;
}

bool pe_header::process_pe_header()
{
    if (_options->Verbose)
        fprintf(stdout, "INFO: Loading PE header for %s.\n", get_name());

    if (_stream != nullptr)
    {
        _raw_header_size = _stream->block_size(0);
        _raw_header = new unsigned char[_raw_header_size];

        if (_raw_header_size >= 0x500)
        {
            if (_stream->read(0, _raw_header_size, _raw_header, &_raw_header_size) && _raw_header_size >= 0x500)
            {
                if (_raw_header_size > sizeof(IMAGE_DOS_HEADER))
                {
                    _header_dos = (IMAGE_DOS_HEADER*) _raw_header;
                    if (_header_dos->e_magic == 0x5A4D)
                    {
                        _parsed_dos = true;
                        unsigned char* base_pe = _header_dos->e_lfanew + _raw_header;

                        if (_test_read(_raw_header, _raw_header_size, base_pe, sizeof(IMAGE_NT_HEADERS64)))
                        {
                            if (((IMAGE_NT_HEADERS32*) base_pe)->Signature == 0x4550 &&
                                ((IMAGE_NT_HEADERS32*) base_pe)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                            {
                                _header_pe32 = (IMAGE_NT_HEADERS32*) base_pe;
                                _parsed_pe_32 = true;
                                if (_options->Verbose)
                                    fprintf(stdout, "INFO: Loaded PE header for %s. Somewhat parsed: %d\n", get_name(), somewhat_parsed());
                                return true;
                            }
                            else if (((IMAGE_NT_HEADERS64*) base_pe)->Signature == 0x4550 &&
                                     ((IMAGE_NT_HEADERS64*) base_pe)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                            {
                                _header_pe64 = (IMAGE_NT_HEADERS64*) base_pe;
                                _parsed_pe_64 = true;
                                if (_options->Verbose)
                                    fprintf(stdout, "INFO: Loaded PE header for %s. Somewhat parsed: %d\n", get_name(), somewhat_parsed());
                                return true;
                            }
                            else
                            {
                                if (_options->Verbose)
                                    fprintf(stdout, "INFO: Invalid PE header for %s. Somewhat parsed: %d\n", get_name(), somewhat_parsed());
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        if (_options->Verbose)
            fprintf(stderr, "INFO: Invalid stream.\n");
    }

    if (_options->Verbose)
        fprintf(stdout, "INFO: Loaded PE header for %s. Somewhat parsed: %d\n", get_name(), somewhat_parsed());
    return false;
}

bool pe_header::process_sections()
{
    if (_options->Verbose)
        fprintf(stdout, "INFO: Loading sections for %s.\n", get_name());

    if (_parsed_pe_32)
    {
        unsigned char* base_pe       = _header_dos->e_lfanew + _raw_header;
        unsigned char* base_sections = base_pe + sizeof(*_header_pe32);

        if (_header_pe32->FileHeader.NumberOfSections > 0x100)
        {
            char* location = new char[FILEPATH_SIZE + 1];
            _stream->get_location(location, FILEPATH_SIZE + 1);
            fprintf(stderr, "WARNING: module '%s' at %s. Extremely large number of sections of 0x%x changed to 0x100 as part of sanity check.\n",
                get_name(), location, _header_pe32->FileHeader.NumberOfSections);
            _header_pe32->FileHeader.NumberOfSections = 0x100;
            delete[] location;
        }

        if (_test_read(_raw_header, _raw_header_size, base_sections, sizeof(IMAGE_SECTION_HEADER)))
        {
            if (!_test_read(_raw_header, _raw_header_size, base_sections,
                    _header_pe32->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
            {
                char* location = new char[FILEPATH_SIZE + 1];
                _stream->get_location(location, FILEPATH_SIZE + 1);
                fprintf(stderr, "WARNING: module '%s' at %s. Number of sections being changed from 0x%x to 0x%x such that it will fit within the PE header buffer.\n",
                    get_name(), location,
                    _header_pe32->FileHeader.NumberOfSections,
                    ((_raw_header + _raw_header_size - base_sections - 1) / sizeof(IMAGE_SECTION_HEADER)));
                delete[] location;
                _header_pe32->FileHeader.NumberOfSections =
                    (WORD)((_raw_header + _raw_header_size - base_sections - 1) / sizeof(IMAGE_SECTION_HEADER));
            }

            _parsed_sections = true;
            _num_sections    = _header_pe32->FileHeader.NumberOfSections;
            _header_sections = (IMAGE_SECTION_HEADER*) base_sections;

            if (_options->Verbose)
            {
                for (int i = 0; i < _num_sections; i++)
                {
                    if (_test_read(_raw_header, _raw_header_size, _header_sections[i].Name, 0x40))
                        fprintf(stdout, "INFO: %s\t#%i\t%s\t0x%x\t0x%x\n",
                            get_name(), i, _header_sections[i].Name,
                            _header_sections[i].VirtualAddress, _header_sections[i].SizeOfRawData);
                    else
                        fprintf(stdout, "INFO: %s\t#%i\tINVALID ADDRESS\t0x%x\t0x%x\n",
                            get_name(), i,
                            _header_sections[i].VirtualAddress, _header_sections[i].SizeOfRawData);
                }
            }

            DWORD image_size = 0;
            if (_num_sections > 0)
            {
                if (_header_sections[_num_sections - 1].Misc.VirtualSize > MAX_SECTION_SIZE)
                {
                    if (_header_pe32->OptionalHeader.SizeOfImage > _header_sections[_num_sections - 1].VirtualAddress &&
                        _header_pe32->OptionalHeader.SizeOfImage < _header_sections[_num_sections - 1].VirtualAddress + MAX_SECTION_SIZE)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Image size of last section appears incorrect, using image size specified by optional header instead since it appears valid.\n",
                            get_name(), location);
                        delete[] location;
                        image_size = _header_pe32->OptionalHeader.SizeOfImage;
                    }
                    else
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Image size of last section appears incorrect, using built-in max section size of 0x%x instead.\n",
                            get_name(), location, MAX_SECTION_SIZE * (_num_sections + 1));
                        delete[] location;
                        image_size = _header_sections[_num_sections - 1].VirtualAddress + MAX_SECTION_SIZE;
                    }
                }
                else
                    image_size = _header_sections[_num_sections - 1].VirtualAddress +
                                 _header_sections[_num_sections - 1].Misc.VirtualSize;
            }
            if (_header_pe32->OptionalHeader.SizeOfImage > image_size)
                image_size = _header_pe32->OptionalHeader.SizeOfImage;

            if (image_size > (DWORD) MAX_SECTION_SIZE * (_num_sections + 1))
            {
                char* location = new char[FILEPATH_SIZE + 1];
                _stream->get_location(location, FILEPATH_SIZE + 1);
                fprintf(stderr, "WARNING: module '%s' at %s. Large image size of 0x%x changed to 0x%x as part of sanity check.\n",
                    get_name(), location,
                    image_size, MAX_SECTION_SIZE * (_num_sections + 1));
                delete[] location;
                image_size = MAX_SECTION_SIZE * (_num_sections + 1);
            }

            _image_size = image_size;
            _image = new unsigned char[_image_size];
            memset(_image, 0, _image_size);

            if (_stream->file_alignment)
            {
                SIZE_T num_read = 0;
                if (_test_read(_image, _image_size, _image, _header_pe32->OptionalHeader.SizeOfHeaders))
                {
                    if (!_stream->read(0, _header_pe32->OptionalHeader.SizeOfHeaders, _image, &num_read) && _options->Verbose)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in header of size 0x%x. Was only able to read 0x%x bytes.\n",
                            get_name(), location, _header_pe32->OptionalHeader.SizeOfHeaders, (unsigned) num_read);
                        delete[] location;
                    }
                }
                else
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in header.\n", get_name(), location);
                    delete[] location;
                }

                if (_parsed_sections)
                {
                    for (int i = 0; i < _num_sections; i++)
                    {
                        if (_test_read(_image, _image_size,
                            _image + (SIZE_T) _header_sections[i].VirtualAddress, _header_sections[i].SizeOfRawData))
                        {
                            if (!_stream->read(_header_sections[i].PointerToRawData, _header_sections[i].SizeOfRawData,
                                _image + (SIZE_T) _header_sections[i].VirtualAddress, &num_read) && _options->Verbose)
                            {
                                char* location = new char[FILEPATH_SIZE + 1];
                                _stream->get_location(location, FILEPATH_SIZE + 1);
                                fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in section %i of size 0x%x. Was only able to read 0x%x bytes.\n",
                                    get_name(), location, i, _header_sections[i].SizeOfRawData, (unsigned) num_read);
                                delete[] location;
                            }
                        }
                    }
                }
            }
            else
            {
                SIZE_T num_read = 0;
                if (!_stream->read(0, _image_size, _image, &num_read) && _options->Verbose)
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in image at 0x%llX of size 0x%x. Was only able to read 0x%x bytes.\n",
                        get_name(), location, _stream->get_address(), (unsigned) _image_size, (unsigned) num_read);
                    delete[] location;
                }
            }

            if (_options->Verbose)
                fprintf(stdout, "INFO: Loaded sections for %s with result: %d. %i sections found.\n",
                    get_name(), _parsed_sections, _parsed_sections ? _num_sections : 0);
            return true;
        }
    }
    else if (_parsed_pe_64)
    {
        unsigned char* base_pe       = _header_dos->e_lfanew + _raw_header;
        unsigned char* base_sections = base_pe + sizeof(*_header_pe64);

        if (_header_pe64->FileHeader.NumberOfSections > 0x100)
        {
            char* location = new char[FILEPATH_SIZE + 1];
            _stream->get_location(location, FILEPATH_SIZE + 1);
            fprintf(stderr, "WARNING: module '%s' at %s. Extremely large number of sections of 0x%x changed to 0x100 as part of sanity check.\n",
                get_name(), location, _header_pe64->FileHeader.NumberOfSections);
            _header_pe64->FileHeader.NumberOfSections = 0x100;
            delete[] location;
        }

        if (_test_read(_raw_header, _raw_header_size, base_sections, sizeof(IMAGE_SECTION_HEADER)))
        {
            if (!_test_read(_raw_header, _raw_header_size, base_sections,
                    _header_pe64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
            {
                char* location = new char[FILEPATH_SIZE + 1];
                _stream->get_location(location, FILEPATH_SIZE + 1);
                fprintf(stderr, "WARNING: module '%s' at %s. Number of sections being changed from 0x%x to 0x%x such that it will fit within the PE header buffer.\n",
                    get_name(), location,
                    _header_pe64->FileHeader.NumberOfSections,
                    ((_raw_header + _raw_header_size - base_sections - 1) / sizeof(IMAGE_SECTION_HEADER)));
                delete[] location;
                _header_pe64->FileHeader.NumberOfSections =
                    (WORD)((_raw_header + _raw_header_size - base_sections - 1) / sizeof(IMAGE_SECTION_HEADER));
            }

            _parsed_sections = true;
            _num_sections    = _header_pe64->FileHeader.NumberOfSections;
            _header_sections = (IMAGE_SECTION_HEADER*) base_sections;

            if (_options->Verbose)
            {
                for (int i = 0; i < _num_sections; i++)
                    fprintf(stdout, "INFO: %s\t#%i\t%s\t0x%x\t0x%x\n",
                        get_name(), i, _header_sections[i].Name,
                        _header_sections[i].VirtualAddress, _header_sections[i].SizeOfRawData);
            }

            DWORD image_size = 0;
            if (_num_sections > 0)
            {
                if (_header_sections[_num_sections - 1].Misc.VirtualSize > MAX_SECTION_SIZE)
                {
                    if (_header_pe64->OptionalHeader.SizeOfImage > _header_sections[_num_sections - 1].VirtualAddress &&
                        _header_pe64->OptionalHeader.SizeOfImage < _header_sections[_num_sections - 1].VirtualAddress + MAX_SECTION_SIZE)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Image size of last section appears incorrect, using image size specified by optional header instead since it appears valid.\n",
                            get_name(), location);
                        delete[] location;
                        image_size = _header_pe64->OptionalHeader.SizeOfImage;
                    }
                    else
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Image size of last section appears incorrect, using built-in max section size of 0x%x instead.\n",
                            get_name(), location, MAX_SECTION_SIZE * (_num_sections + 1));
                        delete[] location;
                        image_size = _header_sections[_num_sections - 1].VirtualAddress + MAX_SECTION_SIZE;
                    }
                }
                else
                    image_size = _header_sections[_num_sections - 1].VirtualAddress +
                                 _header_sections[_num_sections - 1].Misc.VirtualSize;
            }
            if (_header_pe64->OptionalHeader.SizeOfImage > image_size)
                image_size = _header_pe64->OptionalHeader.SizeOfImage;

            if (image_size > (DWORD) MAX_SECTION_SIZE * (_num_sections + 1))
            {
                char* location = new char[FILEPATH_SIZE + 1];
                _stream->get_location(location, FILEPATH_SIZE + 1);
                fprintf(stderr, "WARNING: module '%s' at %s. Large image size of 0x%x changed to 0x%x as part of sanity check.\n",
                    get_name(), location,
                    image_size, MAX_SECTION_SIZE * (_num_sections + 1));
                delete[] location;
                image_size = MAX_SECTION_SIZE * (_num_sections + 1);
            }

            _image_size = image_size;
            _image = new unsigned char[_image_size];
            memset(_image, 0, _image_size);

            if (_stream->file_alignment)
            {
                SIZE_T num_read = 0;
                if (_test_read(_image, _image_size, _image, _header_pe64->OptionalHeader.SizeOfHeaders))
                {
                    if (!_stream->read(0, _header_pe64->OptionalHeader.SizeOfHeaders, _image, &num_read) && _options->Verbose)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in header of size 0x%x. Was only able to read 0x%x bytes.\n",
                            get_name(), location, _header_pe64->OptionalHeader.SizeOfHeaders, (unsigned) num_read);
                        delete[] location;
                    }
                }
                else
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in header.\n", get_name(), location);
                    delete[] location;
                }

                if (_parsed_sections)
                {
                    for (int i = 0; i < _num_sections; i++)
                    {
                        if (_test_read(_image, _image_size,
                            _image + (SIZE_T) _header_sections[i].VirtualAddress, _header_sections[i].SizeOfRawData))
                        {
                            if (!_stream->read(_header_sections[i].PointerToRawData, _header_sections[i].SizeOfRawData,
                                _image + (SIZE_T) _header_sections[i].VirtualAddress, &num_read) && _options->Verbose)
                            {
                                char* location = new char[FILEPATH_SIZE + 1];
                                _stream->get_location(location, FILEPATH_SIZE + 1);
                                fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in section %i of size 0x%x. Was only able to read 0x%x bytes.\n",
                                    get_name(), location, i, _header_sections[i].SizeOfRawData, (unsigned) num_read);
                                delete[] location;
                            }
                        }
                    }
                }
            }
            else
            {
                SIZE_T num_read = 0;
                if (!_stream->read(0, _image_size, _image, &num_read) && _options->Verbose)
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    fprintf(stderr, "WARNING: module '%s' at %s. Failed to read in image at 0x%llX of size 0x%x. Was only able to read 0x%x bytes.\n",
                        get_name(), location, _stream->get_address(), (unsigned) _image_size, (unsigned) num_read);
                    delete[] location;
                }
            }

            if (_options->Verbose)
                fprintf(stdout, "INFO: Loaded sections for %s with result: %d. %i sections found.\n",
                    get_name(), _parsed_sections, _parsed_sections ? _num_sections : 0);
            return true;
        }
    }

    if (_options->Verbose)
        fprintf(stdout, "INFO: Failed to load sections for %s.\n", get_name());
    return false;
}

bool pe_header::process_disk_image(export_list* exports, pe_hash_database* hash_database)
{
    if (_parsed_sections)
    {
        if (_parsed_pe_32)
        {
            // Corrupt/zero alignment causes integer division-by-zero in _section_align
            if (_header_pe32->OptionalHeader.SectionAlignment == 0 ||
                _header_pe32->OptionalHeader.FileAlignment   == 0)
                return false;

            if (_header_pe32->OptionalHeader.AddressOfEntryPoint == 0 ||
                _header_pe32->OptionalHeader.AddressOfEntryPoint == 0x2000 ||
                !_test_read(_image, _image_size, _image + _header_pe32->OptionalHeader.AddressOfEntryPoint, 20) ||
                _options->ForceReconstructEntryPoint)
            {
                printf("INFO: Re-building entrypoint. Original entrypoint invalid: %x\n",
                    _header_pe32->OptionalHeader.AddressOfEntryPoint);

                unsigned __int64 best_entrypoint = 0;
                for (__int64 offset = 0x1000; offset < _image_size - 8; offset += 1)
                {
                    unsigned __int64 cand = *((__int64*) (_image + offset));
                    if (hash_database->contains_epshort(cand))
                    {
                        if (best_entrypoint == 0) best_entrypoint = offset;
                        if (_options->Verbose)
                            printf("INFO: Possible entrypoint found (weak): %x\n", (unsigned) offset);
                        cand = _hash_asm((SIZE_T) offset);
                        if (hash_database->contains_ep(cand))
                        {
                            best_entrypoint = offset;
                            printf("INFO: Possible entrypoint found (strong): %x\n", (unsigned) offset);
                            if (!_options->Verbose) break;
                        }
                    }
                }
                if (best_entrypoint != 0)
                {
                    _header_pe32->OptionalHeader.AddressOfEntryPoint = (DWORD) best_entrypoint;
                    printf("INFO: Updated entrypoint to: %x\n", (unsigned) best_entrypoint);
                }
            }

            unsigned char* larger_image;
            __int64 larger_image_size;
            if (_options->ImportRec && _num_sections > 0)
            {
                pe_imports* peimp = new pe_imports(_image, _image_size, _header_import_descriptors, false);
                int count = 0;
                unsigned __int64 cand_last = 0;
                for (__int64 offset = 0; offset < _image_size - 8; offset += 4)
                {
                    unsigned __int64 cand = *((__int32*) (_image + offset));
                    if (cand_last != cand && exports->contains(cand))
                    {
                        export_entry entry = exports->find(cand);
                        if (entry.name != nullptr)
                            peimp->add_fixup(entry.library_name, entry.name, offset, _parsed_pe_64);
                        else
                            peimp->add_fixup(entry.library_name, entry.ord, offset, _parsed_pe_64);
                        count++;
                    }
                    else
                        cand_last = (unsigned __int64) cand;
                }
                if (_options->Verbose)
                    printf("INFO: Reconstructing %i imports.\n", count);

                __int64 descriptor_size = 0, data_size = 0;
                peimp->get_table_size(descriptor_size, data_size);
                __int64 new_section_size = _section_align(data_size + descriptor_size,
                    _header_pe32->OptionalHeader.SectionAlignment);

                _header_sections[_num_sections - 1].Misc.VirtualSize =
                    _section_align(_header_sections[_num_sections - 1].Misc.VirtualSize,
                        _header_pe32->OptionalHeader.SectionAlignment) + new_section_size;
                _header_sections[_num_sections - 1].SizeOfRawData =
                    _header_sections[_num_sections - 1].Misc.VirtualSize;

                larger_image_size = _section_align((long long) _image_size,
                    _header_pe32->OptionalHeader.SectionAlignment) + new_section_size;
                larger_image = new unsigned char[larger_image_size];
                memset(larger_image, 0, larger_image_size);
                memcpy(larger_image, _image, _image_size);

                if (_options->Verbose) printf("INFO: Writing added import table.\n");
                peimp->build_table(
                    larger_image + _section_align((long long) _image_size, _header_pe32->OptionalHeader.SectionAlignment),
                    new_section_size, (__int64) _image_size, (__int64) 0, descriptor_size);

                if (_options->Verbose) printf("INFO: Updating import data directory.\n");
                _header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
                    (DWORD) _section_align((long long) _image_size, _header_pe32->OptionalHeader.SectionAlignment);
                _header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
                    (DWORD) descriptor_size;
                delete peimp;
            }
            else
            {
                larger_image_size = _image_size;
                larger_image = new unsigned char[larger_image_size];
                memset(larger_image, 0, larger_image_size);
                memcpy(larger_image, _image, _image_size);
            }

            if (_original_base != nullptr)
                _header_pe32->OptionalHeader.ImageBase = (DWORD) _original_base;

            if (_options->Verbose)
                printf("INFO: Adjusting file alignment to %x.\n", _header_pe32->OptionalHeader.SectionAlignment);
            _header_pe32->OptionalHeader.FileAlignment = _header_pe32->OptionalHeader.SectionAlignment;
            _header_pe32->OptionalHeader.SizeOfHeaders =
                _section_align(_header_pe32->OptionalHeader.SizeOfHeaders, _header_pe32->OptionalHeader.FileAlignment);
            DWORD required_space =
                _section_align(_header_pe32->OptionalHeader.SizeOfHeaders, _header_pe32->OptionalHeader.SectionAlignment);

            for (int i = 0; i < _num_sections; i++)
            {
                if (_header_sections[i].Misc.VirtualSize > MAX_SECTION_SIZE)
                {
                    if (_options->Verbose)
                        printf("INFO: Calculating required space for section %i.\n", i);
                    if (i + 1 < _num_sections &&
                        _header_sections[i + 1].VirtualAddress > _header_sections[i].VirtualAddress &&
                        _header_sections[i + 1].VirtualAddress < _header_sections[i].VirtualAddress + MAX_SECTION_SIZE)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x changed to 0x%x based on image size.\n",
                            get_name(), location, i,
                            _header_sections[i].Misc.VirtualSize,
                            _header_sections[i + 1].VirtualAddress - _header_sections[i].VirtualAddress);
                        delete[] location;
                        _header_sections[i].Misc.VirtualSize =
                            _header_sections[i + 1].VirtualAddress - _header_sections[i].VirtualAddress;
                    }
                    else
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x changed to 0x%x based on maximum section size.\n",
                            get_name(), location, i, _header_sections[i].Misc.VirtualSize, MAX_SECTION_SIZE);
                        delete[] location;
                        _header_sections[i].Misc.VirtualSize = MAX_SECTION_SIZE;
                    }
                }
                if ((DWORD)_header_sections[i].Misc.VirtualSize + _header_sections[i].VirtualAddress > larger_image_size)
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    DWORD new_size = (DWORD)(larger_image_size - _header_sections[i].VirtualAddress);
                    fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x being truncated to 0x%x.\n",
                        get_name(), location, i, _header_sections[i].Misc.VirtualSize, new_size);
                    delete[] location;
                    _header_sections[i].Misc.VirtualSize = new_size;
                }
                if (_header_sections[i].Misc.VirtualSize > _header_sections[i].SizeOfRawData)
                    _header_sections[i].SizeOfRawData = _header_sections[i].Misc.VirtualSize;
                _header_sections[i].PointerToRawData = required_space;
                required_space = _section_align(required_space + _header_sections[i].SizeOfRawData,
                    _header_pe32->OptionalHeader.FileAlignment);
            }
            _header_pe32->OptionalHeader.SizeOfImage = required_space;

            if (_options->Verbose)
                printf("INFO: Copying the corrected memory PE header into file PE header format.\n");

            if (_test_read(larger_image, larger_image_size, larger_image, _header_pe32->OptionalHeader.SizeOfHeaders) &&
                _test_read(_raw_header, _raw_header_size, _raw_header, _header_pe32->OptionalHeader.SizeOfHeaders))
                memcpy(larger_image, _raw_header, _header_pe32->OptionalHeader.SizeOfHeaders);
            else if (_test_read(larger_image, larger_image_size, larger_image, _raw_header_size) &&
                     _test_read(_raw_header, _raw_header_size, _raw_header, _raw_header_size))
                memcpy(larger_image, _raw_header, _raw_header_size);

            if (_header_pe32->OptionalHeader.SectionAlignment >= _header_pe32->OptionalHeader.FileAlignment)
            {
                if (_options->Verbose) printf("INFO: Packing down memory sections into the file.\n");
                _disk_image_size = required_space;
                _disk_image = new unsigned char[_disk_image_size];
                memset(_disk_image, 0, _disk_image_size);

                if (_test_read(_disk_image, _disk_image_size, _disk_image,
                    _section_align(_header_pe32->OptionalHeader.SizeOfHeaders, _header_pe32->OptionalHeader.FileAlignment)) &&
                    _test_read(larger_image, larger_image_size, larger_image,
                    _section_align(_header_pe32->OptionalHeader.SizeOfHeaders, _header_pe32->OptionalHeader.FileAlignment)))
                    memcpy(_disk_image, larger_image, _header_pe32->OptionalHeader.SizeOfHeaders);

                if (_parsed_sections)
                {
                    for (int i = 0; i < _num_sections; i++)
                    {
                        if (_options->Verbose) printf("INFO: Packing down section %i.\n", i);
                        if (_test_read(_disk_image, _disk_image_size,
                            _disk_image + (SIZE_T) _header_sections[i].PointerToRawData,
                            _header_sections[i].SizeOfRawData) &&
                            _test_read(larger_image, larger_image_size,
                            larger_image + (SIZE_T) _header_sections[i].VirtualAddress,
                            _header_sections[i].SizeOfRawData))
                        {
                            memcpy(_disk_image + _header_sections[i].PointerToRawData,
                                   larger_image + _header_sections[i].VirtualAddress,
                                   _header_sections[i].SizeOfRawData);
                        }
                    }
                }
                delete[] larger_image;
                if (_options->Verbose) printf("INFO: Done processing disk image.\n");
                return true;
            }
            delete[] larger_image;
        }
        else if (_parsed_pe_64)
        {
            // Corrupt/zero alignment causes integer division-by-zero in _section_align
            if (_header_pe64->OptionalHeader.SectionAlignment == 0 ||
                _header_pe64->OptionalHeader.FileAlignment   == 0)
                return false;

            if (_header_pe64->OptionalHeader.AddressOfEntryPoint == 0 ||
                _header_pe64->OptionalHeader.AddressOfEntryPoint == 0x2000 ||
                !_test_read(_image, _image_size, _image + _header_pe64->OptionalHeader.AddressOfEntryPoint, 20) ||
                _options->ForceReconstructEntryPoint)
            {
                printf("INFO: Re-building entrypoint. Original entrypoint invalid: %x\n",
                    _header_pe64->OptionalHeader.AddressOfEntryPoint);

                unsigned __int64 best_entrypoint = 0;
                for (__int64 offset = 0x1000; offset < _image_size - 8; offset += 1)
                {
                    unsigned __int64 cand = *((__int64*) (_image + offset));
                    if (hash_database->contains_epshort(cand))
                    {
                        if (best_entrypoint == 0) best_entrypoint = offset;
                        if (_options->Verbose)
                            printf("INFO: Possible entrypoint found (weak): %x\n", (unsigned) offset);
                        cand = _hash_asm((SIZE_T) offset);
                        if (hash_database->contains_ep(cand))
                        {
                            best_entrypoint = offset;
                            printf("INFO: Possible entrypoint found (strong): %x\n", (unsigned) offset);
                            if (!_options->Verbose) break;
                        }
                    }
                }
                if (best_entrypoint != 0)
                {
                    _header_pe64->OptionalHeader.AddressOfEntryPoint = (DWORD) best_entrypoint;
                    printf("INFO: Updated entrypoint to: %x\n", (unsigned) best_entrypoint);
                }
            }

            unsigned char* larger_image;
            __int64 larger_image_size;
            if (_options->ImportRec && _num_sections > 0)
            {
                pe_imports* peimp = new pe_imports(_image, _image_size, _header_import_descriptors, true);
                int count = 0;
                unsigned __int64 cand_last = 0;
                for (__int64 offset = 0; offset < _image_size - 8; offset += 4)
                {
                    unsigned __int64 cand = *((unsigned __int64*) (_image + offset));
                    if (cand_last != cand && exports->contains(cand))
                    {
                        export_entry entry = exports->find(cand);
                        if (entry.name != nullptr)
                            peimp->add_fixup(entry.library_name, entry.name, offset, _parsed_pe_64);
                        else
                            peimp->add_fixup(entry.library_name, entry.ord, offset, _parsed_pe_64);
                        count++;
                    }
                    else
                        cand_last = cand;
                }
                if (_options->Verbose)
                    printf("INFO: Reconstructing %i imports.\n", count);

                __int64 descriptor_size = 0, data_size = 0;
                peimp->get_table_size(descriptor_size, data_size);
                __int64 new_section_size = _section_align(data_size + descriptor_size,
                    _header_pe64->OptionalHeader.SectionAlignment);

                _header_sections[_num_sections - 1].Misc.VirtualSize =
                    _section_align(_header_sections[_num_sections - 1].Misc.VirtualSize,
                        _header_pe64->OptionalHeader.SectionAlignment) + new_section_size;
                _header_sections[_num_sections - 1].SizeOfRawData =
                    _header_sections[_num_sections - 1].Misc.VirtualSize;

                larger_image_size = _section_align((long long) _image_size,
                    _header_pe64->OptionalHeader.SectionAlignment) + new_section_size;
                larger_image = new unsigned char[larger_image_size];
                memset(larger_image, 0, larger_image_size);
                memcpy(larger_image, _image, _image_size);

                if (_options->Verbose) printf("INFO: Writing added import table.\n");
                peimp->build_table(
                    larger_image + _section_align((long long) _image_size, _header_pe64->OptionalHeader.SectionAlignment),
                    new_section_size, (__int64) _image_size, (__int64) 0, descriptor_size);

                if (_options->Verbose) printf("INFO: Updating import data directory.\n");
                _header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
                    (DWORD) _section_align((long long) _image_size, _header_pe64->OptionalHeader.SectionAlignment);
                _header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
                    (DWORD) descriptor_size;
                delete peimp;
            }
            else
            {
                larger_image_size = _image_size;
                larger_image = new unsigned char[larger_image_size];
                memset(larger_image, 0, larger_image_size);
                memcpy(larger_image, _image, _image_size);
            }

            if (_original_base != nullptr)
                _header_pe64->OptionalHeader.ImageBase = reinterpret_cast<__int64>(_original_base);

            if (_options->Verbose)
                printf("INFO: Adjusting file alignment to %x.\n", _header_pe64->OptionalHeader.SectionAlignment);
            _header_pe64->OptionalHeader.FileAlignment = _header_pe64->OptionalHeader.SectionAlignment;
            _header_pe64->OptionalHeader.SizeOfHeaders =
                _section_align(_header_pe64->OptionalHeader.SizeOfHeaders, _header_pe64->OptionalHeader.FileAlignment);
            DWORD required_space =
                _section_align(_header_pe64->OptionalHeader.SizeOfHeaders, _header_pe64->OptionalHeader.SectionAlignment);

            for (int i = 0; i < _num_sections; i++)
            {
                if (_header_sections[i].Misc.VirtualSize > MAX_SECTION_SIZE)
                {
                    if (_options->Verbose)
                        printf("INFO: Calculating required space for section %i.\n", i);
                    if (i + 1 < _num_sections &&
                        _header_sections[i + 1].VirtualAddress > _header_sections[i].VirtualAddress &&
                        _header_sections[i + 1].VirtualAddress < _header_sections[i].VirtualAddress + MAX_SECTION_SIZE)
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x changed to 0x%x based on image virtual size.\n",
                            get_name(), location, i,
                            _header_sections[i].Misc.VirtualSize,
                            _header_sections[i + 1].VirtualAddress - _header_sections[i].VirtualAddress);
                        delete[] location;
                        _header_sections[i].Misc.VirtualSize =
                            _header_sections[i + 1].VirtualAddress - _header_sections[i].VirtualAddress;
                    }
                    else
                    {
                        char* location = new char[FILEPATH_SIZE + 1];
                        _stream->get_location(location, FILEPATH_SIZE + 1);
                        fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x changed to 0x%x based on maximum section size.\n",
                            get_name(), location, i, _header_sections[i].Misc.VirtualSize, MAX_SECTION_SIZE);
                        delete[] location;
                        _header_sections[i].Misc.VirtualSize = MAX_SECTION_SIZE;
                    }
                }
                if ((DWORD)_header_sections[i].Misc.VirtualSize + _header_sections[i].VirtualAddress > larger_image_size)
                {
                    char* location = new char[FILEPATH_SIZE + 1];
                    _stream->get_location(location, FILEPATH_SIZE + 1);
                    DWORD new_size = (DWORD)(larger_image_size - _header_sections[i].VirtualAddress);
                    fprintf(stderr, "WARNING: module '%s' at %s. Large section size for section %i of 0x%x being truncated to 0x%x.\n",
                        get_name(), location, i, _header_sections[i].Misc.VirtualSize, new_size);
                    delete[] location;
                    _header_sections[i].Misc.VirtualSize = new_size;
                }
                if (_header_sections[i].Misc.VirtualSize > _header_sections[i].SizeOfRawData)
                    _header_sections[i].SizeOfRawData = _header_sections[i].Misc.VirtualSize;
                _header_sections[i].PointerToRawData = required_space;
                required_space = _section_align(required_space + _header_sections[i].SizeOfRawData,
                    _header_pe64->OptionalHeader.FileAlignment);
            }
            _header_pe64->OptionalHeader.SizeOfImage = required_space;

            if (_options->Verbose)
                printf("INFO: Copying the corrected memory PE header into file PE header format.\n");

            if (_test_read(larger_image, larger_image_size, larger_image, _header_pe64->OptionalHeader.SizeOfHeaders) &&
                _test_read(_raw_header, _raw_header_size, _raw_header, _header_pe64->OptionalHeader.SizeOfHeaders))
                memcpy(larger_image, _raw_header, _header_pe64->OptionalHeader.SizeOfHeaders);
            else if (_test_read(larger_image, larger_image_size, larger_image, _raw_header_size) &&
                     _test_read(_raw_header, _raw_header_size, _raw_header, _raw_header_size))
                memcpy(larger_image, _raw_header, _raw_header_size);

            if (_header_pe64->OptionalHeader.SectionAlignment >= _header_pe64->OptionalHeader.FileAlignment)
            {
                if (_options->Verbose) printf("INFO: Packing down memory sections into the file.\n");
                _disk_image_size = required_space;
                _disk_image = new unsigned char[_disk_image_size];
                memset(_disk_image, 0, _disk_image_size);

                if (_test_read(_disk_image, _disk_image_size, _disk_image,
                    _section_align(_header_pe64->OptionalHeader.SizeOfHeaders, _header_pe64->OptionalHeader.FileAlignment)) &&
                    _test_read(larger_image, larger_image_size, larger_image,
                    _section_align(_header_pe64->OptionalHeader.SizeOfHeaders, _header_pe64->OptionalHeader.FileAlignment)))
                    memcpy(_disk_image, larger_image, _header_pe64->OptionalHeader.SizeOfHeaders);

                if (_parsed_sections)
                {
                    for (int i = 0; i < _num_sections; i++)
                    {
                        if (_options->Verbose) printf("INFO: Packing down section %i.\n", i);
                        if (_test_read(_disk_image, _disk_image_size,
                            _disk_image + (SIZE_T) _header_sections[i].PointerToRawData,
                            _header_sections[i].SizeOfRawData) &&
                            _test_read(larger_image, larger_image_size,
                            larger_image + (SIZE_T) _header_sections[i].VirtualAddress,
                            _header_sections[i].SizeOfRawData))
                        {
                            memcpy(_disk_image + _header_sections[i].PointerToRawData,
                                   larger_image + _header_sections[i].VirtualAddress,
                                   _header_sections[i].SizeOfRawData);
                        }
                    }
                }
                delete[] larger_image;
                if (_options->Verbose) printf("INFO: Done processing disk image.\n");
                return true;
            }
            delete[] larger_image;
        }
    }
    return false;
}

bool pe_header::process_import_directory()
{
    if (_parsed_pe_32)
    {
        if (_header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
        {
            unsigned char* base_imports = _image + _header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            _header_import_descriptors_count = 0;
            bool more;
            do
            {
                more = false;
                if (_test_read(_image, _image_size,
                    base_imports + _header_import_descriptors_count * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)))
                {
                    IMAGE_IMPORT_DESCRIPTOR* current = &((IMAGE_IMPORT_DESCRIPTOR*) base_imports)[_header_import_descriptors_count];
                    if (current->Characteristics != 0 || current->FirstThunk != 0 ||
                        current->ForwarderChain != 0 || current->Name != 0)
                    {
                        more = true;
                        _header_import_descriptors_count++;
                    }
                }
            } while (more);

            if (_options->Verbose)
                printf("Found %i import descriptors.\n", _header_import_descriptors_count);

            if (_header_import_descriptors_count > 0)
            {
                _header_import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) base_imports;
                for (int i = 0; i < _header_import_descriptors_count; i++)
                {
                    int num_iat_entries = 0;
                    bool more2;
                    do
                    {
                        more2 = false;
                        if (_test_read(_image, _image_size,
                            _image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                            sizeof(_IMAGE_THUNK_DATA32)) &&
                            _test_read(_image, _image_size,
                            _image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                            sizeof(_IMAGE_THUNK_DATA32)) &&
                            *((DWORD*) (_image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32))) != 0 &&
                            *((DWORD*) (_image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32))) != 0)
                        {
                            memcpy(_image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                                   _image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                                   sizeof(_IMAGE_THUNK_DATA32));
                            more2 = true;
                            num_iat_entries++;
                        }
                    } while (more2);
                    if (_options->Verbose)
                        printf("Reconstructed %i thunk data entries.\n", num_iat_entries);
                }
            }
        }
        return true;
    }
    else if (_parsed_pe_64)
    {
        if (_header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
        {
            unsigned char* base_imports = _image + _header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            _header_import_descriptors_count = 0;
            bool more;
            do
            {
                more = false;
                if (_test_read(_image, _image_size,
                    base_imports + _header_import_descriptors_count * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)))
                {
                    IMAGE_IMPORT_DESCRIPTOR* current = &((IMAGE_IMPORT_DESCRIPTOR*) base_imports)[_header_import_descriptors_count];
                    if (current->Characteristics != 0 || current->FirstThunk != 0 ||
                        current->ForwarderChain != 0 || current->Name != 0)
                    {
                        more = true;
                        _header_import_descriptors_count++;
                    }
                }
            } while (more);

            if (_options->Verbose)
                printf("Found %i import descriptors.\n", _header_import_descriptors_count);

            if (_header_import_descriptors_count > 0)
            {
                _header_import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) base_imports;
                for (int i = 0; i < _header_import_descriptors_count; i++)
                {
                    int num_iat_entries = 0;
                    bool more2;
                    do
                    {
                        more2 = false;
                        if (_test_read(_image, _image_size,
                            _image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                            sizeof(_IMAGE_THUNK_DATA32)) &&
                            _test_read(_image, _image_size,
                            _image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                            sizeof(_IMAGE_THUNK_DATA32)) &&
                            *((DWORD*) (_image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32))) != 0 &&
                            *((DWORD*) (_image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32))) != 0)
                        {
                            memcpy(_image + _header_import_descriptors[i].FirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                                   _image + _header_import_descriptors[i].OriginalFirstThunk + num_iat_entries * sizeof(_IMAGE_THUNK_DATA32),
                                   sizeof(_IMAGE_THUNK_DATA32));
                            more2 = true;
                            num_iat_entries++;
                        }
                    } while (more2);
                    if (_options->Verbose)
                        printf("Reconstructed %i thunk data entries.\n", num_iat_entries);
                }
            }
        }
        return true;
    }
    return false;
}

bool pe_header::process_export_directory()
{
    _header_import_descriptors_count = 0;
    if ((_parsed_pe_32 || _parsed_pe_64) && _image != nullptr)
    {
        unsigned char* base_exports;
        if (_parsed_pe_32)
            base_exports = _image + _header_pe32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        else
            base_exports = _image + _header_pe64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if (_test_read(_image, _image_size, base_exports, sizeof(IMAGE_EXPORT_DIRECTORY)))
        {
            _header_export_directory = (IMAGE_EXPORT_DIRECTORY*) base_exports;
            _export_list = new export_list();
            _export_list->add_exports(_image, _image_size, (__int64) _original_base,
                _header_export_directory, _parsed_pe_64);
            return true;
        }
    }
    return false;
}

bool pe_header::_test_read(unsigned char* buffer, SIZE_T length, unsigned char* read_ptr, SIZE_T read_length)
{
    return read_ptr >= buffer && read_ptr + read_length <= buffer + length;
}

pe_header::~pe_header()
{
    if (_stream != nullptr)           delete _stream;
    if (_image_size != 0)             delete[] _image;
    if (_raw_header_size != 0)        delete[] _raw_header;
    if (_disk_image_size != 0)        delete[] _disk_image;
    if (_name_filepath_long != 0)     delete[] _name_filepath_long;
    if (_name_filepath_short != 0)    delete[] _name_filepath_short;
    if (_name_original_exports != 0)  delete[] _name_original_exports;
    if (_name_original_manifest != 0) delete[] _name_original_manifest;
    if (_name_symbols_path != 0)      delete[] _name_symbols_path;
    if (_export_list != nullptr)      delete _export_list;
}

DWORD pe_header::_section_align(DWORD address, DWORD alignment)
{
    if (alignment > 0 && address % alignment > 0)
        return (address - (address % alignment)) + alignment;
    return address;
}

__int64 pe_header::_section_align(__int64 address, DWORD alignment)
{
    if (address % alignment > 0)
        return (address - (address % alignment)) + alignment;
    return address;
}
