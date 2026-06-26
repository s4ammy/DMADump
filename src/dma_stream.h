#pragma once

// dma_stream.h — MemProcFS-backed stream_wrapper implementation.
// Replaces process_stream from the reference project.
// All memory reads use VMMDLL_MemReadEx; all region queries use
// a lazily-fetched VAD map instead of VirtualQueryEx.

#include <windows.h>
#include <vmmdll.h>
#include <unordered_map>
#include <string>
#include "options.h"

using namespace std;

// -------------------------------------------------------------------------
// Abstract base (mirrors the original stream_wrapper interface exactly so
// that pe_header.cpp can use dma_stream without any other changes).
// -------------------------------------------------------------------------
class stream_wrapper
{
public:
    bool file_alignment;
    virtual SIZE_T  block_size(long offset)                                                   = 0;
    virtual bool    read(long offset, SIZE_T size, unsigned char* output, SIZE_T* out_read)   = 0;
    virtual SIZE_T  get_short_name(char* out_name, SIZE_T out_name_size)                      = 0;
    virtual SIZE_T  get_long_name(char* out_name, SIZE_T out_name_size)                       = 0;
    virtual SIZE_T  get_location(char* out_name, SIZE_T out_name_size)                        = 0;
    virtual __int64 get_address()                                                              = 0;
    virtual __int64 estimate_section_size(long offset)                                        = 0;
    virtual DWORD   get_region_characteristics(long offset)                                   = 0;
    virtual void    update_base(__int64 rva)                                                   = 0;
    virtual ~stream_wrapper() {}
};


// -------------------------------------------------------------------------
// dma_stream — DMA (MemProcFS) backed stream
// -------------------------------------------------------------------------
class dma_stream : public stream_wrapper
{
    VMM_HANDLE          _hVMM;
    DWORD               _pid;
    void*               _base;
    char*               _long_name;
    char*               _short_name;

    // Lazily-fetched VAD map used for block_size / characteristics queries
    PVMMDLL_MAP_VAD     _vadMap;
    bool                _vadFetched;

    void _ensure_vad()
    {
        if (!_vadFetched)
        {
            _vadFetched = true;
            VMMDLL_Map_GetVadU(_hVMM, _pid, TRUE, &_vadMap);
        }
    }

    // Binary-search the VAD map for the entry that contains 'va'.
    // Returns nullptr if not found.
    PVMMDLL_MAP_VADENTRY _find_vad(ULONG64 va)
    {
        _ensure_vad();
        if (!_vadMap) return nullptr;

        DWORD lo = 0, hi = _vadMap->cMap;
        while (lo < hi)
        {
            DWORD mid = (lo + hi) / 2;
            PVMMDLL_MAP_VADENTRY e = &_vadMap->pMap[mid];
            if (va < e->vaStart)       hi = mid;
            else if (va > e->vaEnd)    lo = mid + 1;
            else                       return e;
        }
        return nullptr;
    }

    // Derive IMAGE_SCN_MEM_* characteristics from MemProcFS VAD protection field.
    // Protection encoding matches Windows MMVAD_FLAGS::Protection nibble.
    static DWORD _vad_protection_to_characteristics(BYTE prot)
    {
        BYTE vl = prot & 7;
        DWORD ch = IMAGE_SCN_MEM_READ; // VAD entries are always readable if committed

        // Execute bit: vl values 2,3,6,7 have execute
        if (vl == 2 || vl == 3 || vl == 6 || vl == 7)
            ch |= IMAGE_SCN_MEM_EXECUTE;

        // Write bit: vl values 4,5,6,7 have write
        if (vl == 4 || vl == 5 || vl == 6 || vl == 7)
            ch |= IMAGE_SCN_MEM_WRITE;

        return ch;
    }

public:
    // Construct from VMM handle + PID + base address.
    // short_name / long_name are optional (may be nullptr) — used for reporting only.
    dma_stream(VMM_HANDLE hVMM, DWORD pid, void* base,
               const char* short_name = nullptr,
               const char* long_name  = nullptr)
        : _hVMM(hVMM), _pid(pid), _base(base),
          _long_name(nullptr), _short_name(nullptr),
          _vadMap(nullptr), _vadFetched(false)
    {
        file_alignment = false;

        if (short_name)
        {
            _short_name = new char[strlen(short_name) + 1];
            strcpy(_short_name, short_name);
        }
        if (long_name)
        {
            _long_name = new char[strlen(long_name) + 1];
            strcpy(_long_name, long_name);
        }
    }

    ~dma_stream() override
    {
        if (_long_name)  delete[] _long_name;
        if (_short_name) delete[] _short_name;
        if (_vadMap)     VMMDLL_MemFree(_vadMap);
    }

    // ----------------------------------------------------------------
    // stream_wrapper interface
    // ----------------------------------------------------------------

    void update_base(__int64 rva) override
    {
        _base = (void*)((__int64)_base + rva);
        // Invalidate cached VAD map since base changed
        if (_vadMap) { VMMDLL_MemFree(_vadMap); _vadMap = nullptr; }
        _vadFetched = false;
    }

    __int64 get_address() override
    {
        return (__int64)_base;
    }

    // Read 'size' bytes from virtual address (base + offset).
    // MemProcFS zero-pads inaccessible pages with VMMDLL_FLAG_ZEROPAD_ON_FAIL,
    // which mirrors ReadProcessMemory's behaviour on guard/noaccess regions.
    bool read(long offset, SIZE_T size, unsigned char* output, SIZE_T* out_read) override
    {
        *out_read = 0;
        if (!output || size == 0) return false;

        ULONG64 va = (ULONG64)((__int64)_base + offset);
        DWORD cbRead = 0;

        BOOL ok = VMMDLL_MemReadEx(_hVMM, _pid, va,
                                   output, (DWORD)size,
                                   &cbRead,
                                   VMMDLL_FLAG_ZEROPAD_ON_FAIL);
        *out_read = cbRead;
        return ok || cbRead > 0;
    }

    // How many bytes are available from (base+offset) to the end of its VAD region.
    SIZE_T block_size(long offset) override
    {
        ULONG64 va = (ULONG64)((__int64)_base + offset);
        PVMMDLL_MAP_VADENTRY e = _find_vad(va);
        if (!e) return 0;
        return (SIZE_T)(e->vaEnd - va + 1);
    }

    // Estimate section size = size of the VAD region containing (base+offset).
    __int64 estimate_section_size(long offset) override
    {
        ULONG64 va = (ULONG64)((__int64)_base + offset);
        PVMMDLL_MAP_VADENTRY e = _find_vad(va);
        if (!e) return 0;
        return (__int64)(e->vaEnd - e->vaStart + 1);
    }

    // Return IMAGE_SCN_MEM_* flags derived from VAD protection at (base+offset).
    DWORD get_region_characteristics(long offset) override
    {
        ULONG64 va = (ULONG64)((__int64)_base + offset);
        PVMMDLL_MAP_VADENTRY e = _find_vad(va);
        if (!e)
            return IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE; // safe default
        return _vad_protection_to_characteristics((BYTE)e->Protection);
    }

    SIZE_T get_short_name(char* out_name, SIZE_T out_name_size) override
    {
        if (_short_name && out_name_size > 0)
        {
            SIZE_T len = strlen(_short_name);
            SIZE_T copy = min(len, out_name_size - 1);
            memcpy(out_name, _short_name, copy);
            out_name[copy] = '\0';
            return copy;
        }
        if (out_name && out_name_size > 0) out_name[0] = '\0';
        return 0;
    }

    SIZE_T get_long_name(char* out_name, SIZE_T out_name_size) override
    {
        if (_long_name && out_name_size > 0)
        {
            SIZE_T len = strlen(_long_name);
            SIZE_T copy = min(len, out_name_size - 1);
            memcpy(out_name, _long_name, copy);
            out_name[copy] = '\0';
            return copy;
        }
        if (out_name && out_name_size > 0) out_name[0] = '\0';
        return 0;
    }

    SIZE_T get_location(char* out_name, SIZE_T out_name_size) override
    {
        if (!out_name || out_name_size == 0) return 0;
        int len = _snprintf(out_name, out_name_size - 1, "0x%llX", (__int64)_base);
        if (len < 0) len = 0;
        out_name[len] = '\0';
        return (SIZE_T)len;
    }
};


// -------------------------------------------------------------------------
// file_stream — file-backed stream (unchanged from reference)
// Kept so pe_hash_database can still load PE files from disk.
// -------------------------------------------------------------------------
class file_stream : public stream_wrapper
{
    char* _filename;
    bool  _opened;
    FILE* _fh;

public:
    file_stream(char* filename)
    {
        file_alignment = true;
        _filename = new char[strlen(filename) + 1];
        strcpy(_filename, filename);
        _fh = fopen(filename, "rb");
        _opened = (_fh != nullptr);
    }

    ~file_stream() override
    {
        if (_opened) fclose(_fh);
        if (_filename) delete[] _filename;
    }

    void update_base(__int64 rva) override {}

    __int64 get_address() override { return 0; }

    __int64 estimate_section_size(long offset) override { return 0; }

    SIZE_T get_location(char* out_name, SIZE_T out_name_size) override
    {
        return get_long_name(out_name, out_name_size);
    }

    SIZE_T get_long_name(char* out_name, SIZE_T out_name_size) override
    {
        if (!_filename || !out_name || out_name_size == 0) return 0;
        SIZE_T len = strlen(_filename);
        SIZE_T copy = min(len, out_name_size - 1);
        memcpy(out_name, _filename, copy);
        out_name[copy] = '\0';
        return copy;
    }

    SIZE_T get_short_name(char* out_name, SIZE_T out_name_size) override
    {
        char fname[_MAX_FNAME], ext[_MAX_EXT], buf[_MAX_FNAME + _MAX_EXT + 2];
        _splitpath(_filename, nullptr, nullptr, fname, ext);
        int len = _snprintf(buf, sizeof(buf) - 1, "%s%s", fname, ext);
        if (len <= 0) { if (out_name && out_name_size) out_name[0] = '\0'; return 0; }
        SIZE_T copy = min((SIZE_T)len, out_name_size - 1);
        memcpy(out_name, buf, copy);
        out_name[copy] = '\0';
        return copy;
    }

    SIZE_T block_size(long offset) override
    {
        if (!_opened) return 0;
        fseek(_fh, 0, SEEK_END);
        long end = ftell(_fh);
        fseek(_fh, 0, SEEK_SET);
        return (SIZE_T)max(0L, end - offset);
    }

    DWORD get_region_characteristics(long offset) override
    {
        return IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }

    bool read(long offset, SIZE_T size, unsigned char* output, SIZE_T* out_read) override
    {
        *out_read = 0;
        if (!_opened) return false;
        if (fseek(_fh, offset, SEEK_SET) != 0) return false;
        *out_read = fread(output, 1, size, _fh);
        return *out_read == size;
    }
};
