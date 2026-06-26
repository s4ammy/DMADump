#pragma once

// dma_process.h — DMA-based process dumper.
// Replaces dump_process.h from the reference project.
// No Windows process-access APIs are used; everything goes through MemProcFS.

#include <windows.h>
#include <vmmdll.h>
#include <unordered_set>
#include <set>

#include "options.h"
#include "dma_module_list.h"
#include "export_list.h"
#include "pe_hash_database.h"

using namespace std;

#define DMA_PAGE_SIZE         0x1000
#define DMA_CODECHUNK_HDRSZ   0x200   // bytes CRC32'd per code chunk header
#define DMA_CODECHUNK_LIMIT   500     // max novel code chunks deeply processed

// Minimal memory region descriptor (mirrors MBI_BASIC_INFO from reference)
struct DMA_REGION_INFO
{
    ULONG64 base;
    ULONG64 end;
    DWORD   protection;   // raw VAD protection nibble
    bool    valid;        // committed & accessible
    bool    executable;   // has execute permission
    bool    is_image;     // VAD type is image (fImage)
    bool    is_private;   // private memory (fPrivateMemory)
};


class dma_process
{
    VMM_HANDLE          _hVMM;
    DWORD               _pid;
    char*               _process_name;
    bool                _opened;

    pe_hash_database*   _db_clean;
    PD_OPTIONS*         _options;

    export_list         _export_list;
    bool                _export_list_built;

    // Cached VAD map for the current dump cycle
    PVMMDLL_MAP_VAD     _vadMap;
    bool                _vadFetched;

    // ----------------------------------------------------------------
    // Private helpers
    // ----------------------------------------------------------------
    void             _ensure_vad();
    DMA_REGION_INFO  _get_region_info(ULONG64 address);

    bool             _build_export_list();
    bool             _build_export_list_for(export_list* result, const char* libname,
                                             dma_module_list* modules);

    void             _dump_pe_at(ULONG64 base, dma_module_list* modules,
                                  const char* label, bool force_gen_header);

    void             _scan_manual_maps(dma_module_list* modules, set<ULONG64>& dumped_bases);

    unsigned __int64 _hash_chunk_header(ULONG64 base);

public:
    dma_process(VMM_HANDLE hVMM, DWORD pid, pe_hash_database* db, DMADUMP_OPTIONS* opts);
    ~dma_process();

    // Main entry point — dumps all PE images (normal + hidden) from the process
    void dump_all();

    DWORD       get_pid() const { return _pid; }
    const char* get_name() const { return _process_name ? _process_name : "unknown"; }
    bool        is_opened() const { return _opened; }
    bool        is64();
};
