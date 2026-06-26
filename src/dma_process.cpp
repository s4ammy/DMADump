// dma_process.cpp — DMA-based process dumper implementation.
// No Windows process-access APIs (OpenProcess / ReadProcessMemory /
// VirtualQueryEx / EnumProcessModulesEx) are used anywhere in this file.

#include <windows.h>
#include <Shlwapi.h>
#include <vmmdll.h>
#include <stdio.h>
#include <set>
#include <unordered_set>

#include "dma_process.h"
#include "dma_module_list.h"
#include "dma_stream.h"
#include "pe_header.h"
#include "hash.h"

using namespace std;


// ============================================================
// Construction / Destruction
// ============================================================

dma_process::dma_process(VMM_HANDLE hVMM, DWORD pid,
                         pe_hash_database* db, DMADUMP_OPTIONS* opts)
    : _hVMM(hVMM), _pid(pid),
      _db_clean(db), _options(opts),
      _export_list_built(false),
      _vadMap(nullptr), _vadFetched(false),
      _opened(false), _process_name(nullptr)
{
    // Fetch process name via MemProcFS
    VMMDLL_PROCESS_INFORMATION info = {};
    info.magic   = VMMDLL_PROCESS_INFORMATION_MAGIC;
    info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    SIZE_T cbInfo = sizeof(info);

    if (VMMDLL_ProcessGetInformation(_hVMM, _pid, &info, &cbInfo))
    {
        _opened = true;
        const char* src = info.szNameLong[0] ? info.szNameLong : info.szName;
        size_t len = strlen(src);
        _process_name = new char[len + 1];
        strcpy(_process_name, src);

        // Replace '.' with '_' (matches reference behaviour)
        for (size_t i = 0; i < len; i++)
            if (_process_name[i] == '.') _process_name[i] = '_';
    }
    else
    {
        // Still try to work even if we can't get the name
        _opened = true;
        _process_name = new char[8];
        strcpy(_process_name, "unknown");
        if (_options->Verbose)
            fprintf(stderr, "WARNING: Could not get process info for PID 0x%x\n", pid);
    }
}

dma_process::~dma_process()
{
    delete[] _process_name;
    if (_vadMap) VMMDLL_MemFree(_vadMap);
}


// ============================================================
// Private helpers
// ============================================================

void dma_process::_ensure_vad()
{
    if (!_vadFetched)
    {
        _vadFetched = true;
        VMMDLL_Map_GetVadU(_hVMM, _pid, TRUE, &_vadMap);
    }
}

// Returns region info for the VAD entry that contains 'address'.
// Replaces the old VirtualQueryEx-based get_mbi_info().
DMA_REGION_INFO dma_process::_get_region_info(ULONG64 address)
{
    DMA_REGION_INFO r = {};

    _ensure_vad();
    if (!_vadMap) return r;

    // Linear scan (could be binary-searched, but VAD maps are small)
    for (DWORD i = 0; i < _vadMap->cMap; i++)
    {
        PVMMDLL_MAP_VADENTRY e = &_vadMap->pMap[i];
        if (address >= e->vaStart && address <= e->vaEnd)
        {
            r.base       = e->vaStart;
            r.end        = e->vaEnd + 1;   // exclusive end (matches MBI semantics)
            r.protection = (DWORD)e->Protection;
            r.valid      = true;
            r.is_image   = e->fImage  ? true : false;
            r.is_private = e->fPrivateMemory ? true : false;

            // Execute check from protection nibble (low 3 bits)
            BYTE vl = (BYTE)(e->Protection & 7);
            r.executable = (vl == 2 || vl == 3 || vl == 6 || vl == 7);
            return r;
        }
    }
    return r;   // not found
}

bool dma_process::is64()
{
    // Read the NT header Machine field from the main module
    BYTE buf[0x200] = {};
    DWORD cbRead = 0;

    // Get the main module base (first entry of module list)
    PVMMDLL_MAP_MODULE pMap = nullptr;
    if (!VMMDLL_Map_GetModuleU(_hVMM, _pid, &pMap, VMMDLL_MODULE_FLAG_NORMAL))
        return true; // assume 64-bit on failure

    ULONG64 mainBase = 0;
    if (pMap->cMap > 0) mainBase = pMap->pMap[0].vaBase;
    VMMDLL_MemFree(pMap);

    if (!mainBase) return true;

    VMMDLL_MemReadEx(_hVMM, _pid, mainBase, buf, sizeof(buf), &cbRead, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
    if (cbRead < 0x40) return true;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
    if (dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > cbRead) return true;

    DWORD sig = *(DWORD*)(buf + dos->e_lfanew);
    if (sig != IMAGE_NT_SIGNATURE) return true;

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(buf + dos->e_lfanew + sizeof(DWORD));
    return fh->Machine == IMAGE_FILE_MACHINE_AMD64 ||
           fh->Machine == IMAGE_FILE_MACHINE_ARM64;
}


// ============================================================
// Export list building (for import reconstruction)
// ============================================================

bool dma_process::_build_export_list()
{
    if (_export_list_built) return true;

    if (!_options->Verbose == false)
        printf("... building import reconstruction table ...\n");
    else
        printf("... building import reconstruction table ...\n");

    dma_module_list* modules = new dma_module_list(_hVMM, _pid, _options->Verbose);

    for (auto& kv : modules->_modules)
    {
        dma_module* mod = kv.second;
        dma_stream* stream = new dma_stream(_hVMM, _pid, (void*)mod->va_base,
                                             mod->short_name, mod->full_name);

        pe_header* header = new pe_header(stream, modules, _options);
        if (header->process_pe_header() &&
            header->process_sections()  &&
            header->process_export_directory())
        {
            _export_list.add_exports(header->get_exports());
        }
        delete header;
        // stream is owned and deleted by pe_header
    }

    delete modules;
    _export_list_built = true;
    return true;
}

bool dma_process::_build_export_list_for(export_list* result,
                                          const char* libname,
                                          dma_module_list* modules)
{
    for (auto& kv : modules->_modules)
    {
        dma_module* mod = kv.second;
        if (_stricmp(mod->short_name, libname) != 0) continue;

        dma_stream* stream = new dma_stream(_hVMM, _pid, (void*)mod->va_base,
                                             mod->short_name, mod->full_name);
        pe_header* header = new pe_header(stream, modules, _options);
        if (header->process_pe_header() &&
            header->process_sections()  &&
            header->process_export_directory())
        {
            result->add_exports(header->get_exports());
        }
        delete header;
    }
    return true;
}


// ============================================================
// CRC32 hash of first DMA_CODECHUNK_HDRSZ bytes at 'base'
// ============================================================

unsigned __int64 dma_process::_hash_chunk_header(ULONG64 base)
{
    char buf[DMA_CODECHUNK_HDRSZ] = {};
    DWORD cbRead = 0;

    VMMDLL_MemReadEx(_hVMM, _pid, base, (PBYTE)buf, DMA_CODECHUNK_HDRSZ,
                     &cbRead, VMMDLL_FLAG_ZEROPAD_ON_FAIL);

    if (cbRead > 8)
        return (unsigned __int64)crc32buf(buf, cbRead);

    return 0;
}


// ============================================================
// Dump a single PE image at 'base'
// ============================================================

void dma_process::_dump_pe_at(ULONG64 base, dma_module_list* modules,
                               const char* label, bool force_gen_header)
{
    auto do_dump = [&](bool amd64)
    {
        dma_stream* stream = new dma_stream(_hVMM, _pid, (void*)base);
        pe_header*  header = new pe_header(stream, modules, _options);

        if (!force_gen_header)
        {
            // Try to use the existing PE header in memory
            if (!header->process_pe_header())
            {
                delete header;
                return;
            }
        }
        else
        {
            header->build_pe_header(0x1000, amd64);
        }

        // Guard against absurdly large images (> 200 MB) crashing the process
        if (header->get_virtual_size() > (ULONG64)200 * 1024 * 1024)
        {
            if (_options->Verbose)
                printf("  [SKIP] Image at 0x%llX claims %llu MB, skipping.\n",
                       (unsigned long long)base,
                       (unsigned long long)(header->get_virtual_size() / (1024 * 1024)));
            delete header;
            return;
        }

        if (!header->process_sections() || !header->somewhat_parsed())
        {
            delete header;
            return;
        }

        if (!header->process_import_directory())
        {
            delete header;
            return;
        }

        unsigned __int64 hash = header->get_hash();
        if (hash == 0 || _db_clean->contains(hash))
        {
            delete header;
            return;
        }

        bool disk_ok = false;
        try
        {
            disk_ok = header->process_disk_image(&_export_list, _db_clean);
        }
        catch (...)
        {
            // DynArray throws MEMFAIL (OOM) if import reconstruction finds an
            // unreasonable number of matches in a corrupt / non-PE image.
            if (_options->Verbose)
                printf("  [SKIP] process_disk_image exception at 0x%llX, skipping.\n",
                       (unsigned long long)base);
            delete header;
            return;
        }
        if (!disk_ok)
        {
            delete header;
            return;
        }

        const char* ext = header->is_exe() ? "exe" :
                          header->is_dll() ? "dll" :
                          header->is_sys() ? "sys" : "bin";

        char filename[MAX_PATH + FILENAME_MAX + 32];
        if (_options->output_path && _options->output_path[0])
            _snprintf(filename, sizeof(filename) - 1,
                      "%s\\%s_PID%x_%s_%llX_%s_%s.%s",
                      _options->output_path, _process_name, _pid,
                      header->get_name(), (unsigned long long)base,
                      label,
                      header->is_64() ? "x64" : "x86",
                      ext);
        else
            _snprintf(filename, sizeof(filename) - 1,
                      "%s_PID%x_%s_%llX_%s_%s.%s",
                      _process_name, _pid,
                      header->get_name(), (unsigned long long)base,
                      label,
                      header->is_64() ? "x64" : "x86",
                      ext);

        printf("  [%s] dumping '%s' at 0x%llX -> '%s'\n",
               label, ext, (unsigned long long)base, filename);

        header->write_image(filename);
        delete header;
    };

    if (force_gen_header)
    {
        // Generate both 64-bit and 32-bit versions when forcing header gen
        do_dump(true);
        do_dump(false);
    }
    else
    {
        do_dump(false); // process_pe_header() decides bitness internally
    }
}


// ============================================================
// _scan_manual_maps — ModFinder-style private allocation scanner
//
// Detects manually mapped DLLs that have no MZ header at their base
// (header erased after mapping).  Strategy:
//   1. Group contiguous private non-image VAD sub-regions into a
//      single allocation.
//   2. Discard if the group has no executable sub-region (not code).
//   3a. If allocation base has an MZ signature   → dump normally.
//   3b. If base sub-region is PAGE_READONLY and
//       a later sub-region is executable          → erased-header
//       manual map → force-generate PE header.
//   3c. Otherwise (only when -chunks / ForceGenHeader set) → try anyway.
// ============================================================

void dma_process::_scan_manual_maps(dma_module_list* modules, set<ULONG64>& dumped_bases)
{
    _ensure_vad();
    if (!_vadMap || _vadMap->cMap == 0) return;

    printf("\n--- Tier 2b: Manual map scan (%u VAD entries) ---\n", _vadMap->cMap);

    DWORD n = _vadMap->cMap;
    DWORD i = 0;

    while (i < n)
    {
        PVMMDLL_MAP_VADENTRY e = &_vadMap->pMap[i];

        // Only interested in private, non-image allocations
        if (e->fImage || !e->fPrivateMemory)
        {
            i++;
            continue;
        }

        // Start of a private non-image group — record base-entry properties
        ULONG64 alloc_base    = e->vaStart;
        ULONG64 group_end     = e->vaEnd + 1;   // exclusive end of current group
        BYTE    base_prot     = (BYTE)(e->Protection & 7);
        bool    has_exec      = (base_prot == 2 || base_prot == 3 ||
                                 base_prot == 6 || base_prot == 7);
        bool    base_readonly = (base_prot == 1);

        // Consume all contiguous private non-image sub-regions
        i++;
        while (i < n)
        {
            PVMMDLL_MAP_VADENTRY cur = &_vadMap->pMap[i];
            if (cur->fImage || !cur->fPrivateMemory) break;
            // Gap larger than one page means a new unrelated allocation
            if (cur->vaStart > group_end + DMA_PAGE_SIZE) break;

            BYTE vl = (BYTE)(cur->Protection & 7);
            if (vl == 2 || vl == 3 || vl == 6 || vl == 7)
                has_exec = true;

            group_end = cur->vaEnd + 1;
            i++;
        }

        ULONG64 alloc_size = group_end - alloc_base;

        // Filter: too small, already processed, or no executable sub-region
        if (alloc_size < 0x10000)           continue;
        if (dumped_bases.count(alloc_base)) continue;
        if (!has_exec)                      continue;

        // Check for MZ signature at the allocation base
        BYTE  mzBuf[2] = {};
        DWORD cbRead   = 0;
        VMMDLL_MemReadEx(_hVMM, _pid, alloc_base, mzBuf, 2,
                         &cbRead, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
        bool has_mz = (cbRead >= 2 && mzBuf[0] == 'M' && mzBuf[1] == 'Z');

        if (has_mz)
        {
            // Header intact — dump with normal PE parsing
            if (_options->Verbose)
                printf("  [MANUALMAP] MZ at private exec alloc 0x%llX (size 0x%llX)\n",
                       (unsigned long long)alloc_base,
                       (unsigned long long)alloc_size);
            _dump_pe_at(alloc_base, modules, "MANUALMAP", false);
            dumped_bases.insert(alloc_base);
        }
        else if (base_readonly)
        {
            // Classic erased-header pattern:
            //   base page = PAGE_READONLY (was set readonly after header erase)
            //   subsequent pages = executable
            // Force-generate a synthetic PE header so sections can be recovered.
            if (_options->Verbose)
                printf("  [MANUALMAP_NH] Erased-header exec alloc 0x%llX (size 0x%llX)\n",
                       (unsigned long long)alloc_base,
                       (unsigned long long)alloc_size);
            _dump_pe_at(alloc_base, modules, "MANUALMAP_NH", true);
            dumped_bases.insert(alloc_base);
        }
        else if (_options->DumpChunks || _options->ForceGenHeader)
        {
            // No MZ and base isn't readonly, but caller asked for aggressive scanning
            if (_options->Verbose)
                printf("  [MANUALMAP_EXEC] Private exec alloc 0x%llX (size 0x%llX)\n",
                       (unsigned long long)alloc_base,
                       (unsigned long long)alloc_size);
            _dump_pe_at(alloc_base, modules, "MANUALMAP_EXEC", true);
            dumped_bases.insert(alloc_base);
        }
    }
}


// ============================================================
// dump_all — main orchestration
// ============================================================

void dma_process::dump_all()
{
    printf("dumping process '%s' PID 0x%x via DMA...\n", _process_name, _pid);

    if (!_build_export_list())
    {
        fprintf(stderr, "ERROR: Failed to build export list for PID 0x%x\n", _pid);
        return;
    }

    // Ensure VAD map is cached
    _ensure_vad();

    // ----------------------------------------------------------------
    // TIER 1 — modules from VMMDLL_Map_GetModuleU
    // MemProcFS already distinguishes NORMAL / NOTLINKED / INJECTED
    // ----------------------------------------------------------------
    PVMMDLL_MAP_MODULE pModMap = nullptr;
    if (!VMMDLL_Map_GetModuleU(_hVMM, _pid, &pModMap, VMMDLL_MODULE_FLAG_NORMAL))
    {
        fprintf(stderr, "ERROR: VMMDLL_Map_GetModuleU failed for PID 0x%x\n", _pid);
        return;
    }

    dma_module_list* modules = new dma_module_list(_hVMM, _pid, _options->Verbose);
    set<ULONG64> dumped_bases;   // track already-processed bases

    printf("\n--- Tier 1: MemProcFS module map (%u entries) ---\n", pModMap->cMap);

    for (DWORD i = 0; i < pModMap->cMap; i++)
    {
        PVMMDLL_MAP_MODULEENTRY e = &pModMap->pMap[i];

        // Skip normal modules when DumpHiddenOnly is set
        if (_options->DumpHiddenOnly && e->tp == VMMDLL_MODULE_TP_NORMAL)
            continue;

        const char* type_label =
            (e->tp == VMMDLL_MODULE_TP_NOTLINKED) ? "NOTLINKED" :
            (e->tp == VMMDLL_MODULE_TP_INJECTED)  ? "INJECTED"  :
            (e->tp == VMMDLL_MODULE_TP_DATA)       ? "DATA"      : "NORMAL";

        if (_options->Verbose || e->tp != VMMDLL_MODULE_TP_NORMAL)
            printf("  [%s] 0x%llX  %s\n",
                   type_label, (unsigned long long)e->vaBase,
                   e->uszText ? e->uszText : "");

        _dump_pe_at(e->vaBase, modules, type_label, _options->ForceGenHeader);
        dumped_bases.insert(e->vaBase);
    }

    VMMDLL_MemFree(pModMap);

    // ----------------------------------------------------------------
    // TIER 2 — VAD cross-reference: fImage entries absent from module map.
    // These are image-backed regions that MemProcFS didn't identify as modules —
    // catches DLLs hidden from the PEB LDR but still mapped as image sections.
    //
    // Noise filter: VAD entries that have a non-empty uszText containing a
    // Windows system path are legitimate DLLs the module walker simply missed —
    // skip those.  Entries with no backing path are suspicious (file deleted,
    // reflective injection, etc.) and are always dumped.
    //
    // Import reconstruction is disabled for these entries to avoid OOM from
    // false-positive export address matches in large system DLLs.
    // ----------------------------------------------------------------
    if (_vadMap)
    {
        printf("\n--- Tier 2: VAD image cross-reference (%u VAD entries) ---\n",
               _vadMap->cMap);

        bool saved_imprec = _options->ImportRec;
        _options->ImportRec = false;   // no import rec for VAD_HIDDEN images

        for (DWORD i = 0; i < _vadMap->cMap; i++)
        {
            PVMMDLL_MAP_VADENTRY e = &_vadMap->pMap[i];
            if (!e->fImage) continue;                     // only image-backed
            if (dumped_bases.count(e->vaStart)) continue; // already dumped

            // Skip known system-path entries — MemProcFS just missed them in
            // the module walk, they are not injected code.
            if (e->uszText && e->uszText[0])
            {
                // Case-insensitive substring check for common system locations
                const char* txt = e->uszText;
                auto ci_find = [&](const char* needle) -> bool {
                    return StrStrIA(txt, needle) != nullptr;
                };
                if (ci_find("\\Windows\\System32\\") ||
                    ci_find("\\Windows\\SysWOW64\\") ||
                    ci_find("\\Windows\\WinSxS\\")   ||
                    ci_find("\\Windows\\System\\"))
                {
                    if (_options->Verbose)
                        printf("  [VAD-SKIP] System image at 0x%llX (%s)\n",
                               (unsigned long long)e->vaStart, txt);
                    continue;
                }
            }

            // Check for MZ signature before attempting full parse
            BYTE mzBuf[2] = {};
            DWORD cbRead = 0;
            VMMDLL_MemReadEx(_hVMM, _pid, e->vaStart, mzBuf, 2,
                             &cbRead, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (cbRead < 2 || mzBuf[0] != 'M' || mzBuf[1] != 'Z')
                continue;

            if (_options->Verbose)
                printf("  [VAD-HIDDEN] Unlisted image at 0x%llX (%s)\n",
                       (unsigned long long)e->vaStart,
                       e->uszText && e->uszText[0] ? e->uszText : "<no path>");

            _dump_pe_at(e->vaStart, modules, "VAD_HIDDEN", false);
            dumped_bases.insert(e->vaStart);
        }

        _options->ImportRec = saved_imprec;
    }

    // ----------------------------------------------------------------
    // TIER 2b — Manual map scan (ModFinder-style).
    // ----------------------------------------------------------------
    _scan_manual_maps(modules, dumped_bases);

    // ----------------------------------------------------------------
    // TIER 3 — Executable private memory scan (optional, DumpChunks mode).
    // Uses the PTE map to enumerate non-NX private pages without an image
    // backing, scans each page-aligned address for an MZ header.
    // Catches manually-mapped DLLs that don't appear as image VADs and
    // raw shellcode PEs decompressed into private allocations.
    // ----------------------------------------------------------------
    if (_options->DumpChunks)
    {
        printf("\n--- Tier 3: Executable private memory scan ---\n");

        PVMMDLL_MAP_PTE pPteMap = nullptr;
        if (VMMDLL_Map_GetPteU(_hVMM, _pid, FALSE, &pPteMap))
        {
            set<ULONG64> exec_pages;

            for (DWORD i = 0; i < pPteMap->cMap; i++)
            {
                PVMMDLL_MAP_PTEENTRY pe = &pPteMap->pMap[i];

                // Skip NX pages and pages that belong to a known image
                if (pe->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX) continue;

                ULONG64 page_va = pe->vaBase;
                DMA_REGION_INFO ri = _get_region_info(page_va);

                // Only consider private (non-image, non-file) executable memory
                if (ri.is_image || !ri.is_private) continue;

                exec_pages.insert(page_va);
            }

            VMMDLL_MemFree(pPteMap);

            int new_chunks = 0;
            for (ULONG64 page_va : exec_pages)
            {
                if (dumped_bases.count(page_va)) continue;

                unsigned __int64 hdr_hash = _hash_chunk_header(page_va);
                if (hdr_hash == 0 || _db_clean->contains(hdr_hash)) continue;
                if (new_chunks++ > DMA_CODECHUNK_LIMIT)
                {
                    printf("  [CHUNK] Too many novel code chunks, stopping.\n");
                    break;
                }

                // Check for MZ header
                BYTE mz[2] = {};
                DWORD cbR = 0;
                VMMDLL_MemReadEx(_hVMM, _pid, page_va, mz, 2,
                                 &cbR, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
                if (cbR < 2 || mz[0] != 'M' || mz[1] != 'Z')
                    continue;

                if (_options->Verbose)
                    printf("  [CHUNK] MZ at private exec page 0x%llX\n",
                           (unsigned long long)page_va);

                _dump_pe_at(page_va, modules, "CHUNK", true);
                dumped_bases.insert(page_va);
            }
        }
    }

    delete modules;
    printf("\nDone dumping process '%s' (PID 0x%x)\n", _process_name, _pid);
}
