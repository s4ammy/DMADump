#pragma once

// dma_module_list.h — MemProcFS-backed module enumeration.
// Replaces module_list.h from the reference project.
// Uses VMMDLL_Map_GetModuleU to enumerate ALL modules including:
//   VMMDLL_MODULE_TP_NORMAL    — standard modules linked in PEB LDR
//   VMMDLL_MODULE_TP_DATA      — data-only mappings
//   VMMDLL_MODULE_TP_NOTLINKED — hidden modules (not in PEB LDR / manually mapped DLLs)
//   VMMDLL_MODULE_TP_INJECTED  — injected modules

#include <windows.h>
#include <vmmdll.h>
#include <unordered_map>
#include <cstdio>

using namespace std;


// One loaded module as seen by MemProcFS.
struct dma_module
{
    ULONG64              va_base;
    DWORD                image_size;
    char*                short_name;   // e.g. "ntdll.dll"
    char*                full_name;    // e.g. "C:\Windows\System32\ntdll.dll"
    VMMDLL_MODULE_TP     tp;           // NORMAL / DATA / NOTLINKED / INJECTED

    dma_module(ULONG64 base, DWORD size, const char* sname, const char* fname, VMMDLL_MODULE_TP type)
        : va_base(base), image_size(size), tp(type)
    {
        short_name = new char[strlen(sname) + 1];
        strcpy(short_name, sname);
        full_name  = new char[strlen(fname) + 1];
        strcpy(full_name, fname);
    }

    // Convenience: is this module hidden from the PEB LDR list?
    bool is_hidden() const
    {
        return tp == VMMDLL_MODULE_TP_NOTLINKED || tp == VMMDLL_MODULE_TP_INJECTED;
    }

    const char* type_str() const
    {
        switch (tp)
        {
        case VMMDLL_MODULE_TP_NORMAL:    return "NORMAL";
        case VMMDLL_MODULE_TP_DATA:      return "DATA";
        case VMMDLL_MODULE_TP_NOTLINKED: return "NOTLINKED";
        case VMMDLL_MODULE_TP_INJECTED:  return "INJECTED";
        default:                         return "UNKNOWN";
        }
    }

    ~dma_module()
    {
        delete[] short_name;
        delete[] full_name;
    }
};


// -------------------------------------------------------------------------
// dma_module_list — builds the complete module map for one process via DMA.
// Keyed by module base address (ULONG64).
// -------------------------------------------------------------------------
class dma_module_list
{
public:
    // Public map so dma_process can iterate freely (same pattern as reference module_list)
    unordered_map<ULONG64, dma_module*> _modules;

    // Empty list (used when only the address is needed with no name info)
    dma_module_list() {}

    // Build module list from MemProcFS
    dma_module_list(VMM_HANDLE hVMM, DWORD pid, bool verbose = false)
    {
        PVMMDLL_MAP_MODULE pMap = nullptr;
        if (!VMMDLL_Map_GetModuleU(hVMM, pid, &pMap, VMMDLL_MODULE_FLAG_NORMAL))
        {
            if (verbose)
                fprintf(stderr, "WARNING: VMMDLL_Map_GetModuleU failed for PID 0x%x\n", pid);
            return;
        }

        for (DWORD i = 0; i < pMap->cMap; i++)
        {
            PVMMDLL_MAP_MODULEENTRY e = &pMap->pMap[i];
            const char* sname = e->uszText     ? e->uszText     : "";
            const char* fname = e->uszFullName  ? e->uszFullName : sname;

            if (_modules.count(e->vaBase) == 0)
                _modules[e->vaBase] = new dma_module(e->vaBase, e->cbImageSize, sname, fname, e->tp);
        }

        VMMDLL_MemFree(pMap);

        if (verbose)
            fprintf(stdout, "INFO: Enumerated %zu modules for PID 0x%x\n", _modules.size(), pid);
    }

    ~dma_module_list()
    {
        for (auto& kv : _modules)
            delete kv.second;
    }

    // Look up by base address — returns nullptr if not found
    dma_module* find(ULONG64 base) const
    {
        auto it = _modules.find(base);
        return it != _modules.end() ? it->second : nullptr;
    }
};
