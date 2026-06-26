// main.cpp — DMADump entry point.
// Initialises MemProcFS via VMMDLL_Initialize, enumerates target PIDs
// (either by explicit -pid or by name regex via -p), then calls
// dma_process::dump_all() for each target.

#include <windows.h>
#include <vmmdll.h>
#include <stdio.h>
#include <string.h>
#include <regex>
#include <string>
#include <vector>

#include "options.h"
#include "dma_process.h"
#include "pe_hash_database.h"

using namespace std;

// -----------------------------------------------------------------------
// Print usage
// -----------------------------------------------------------------------
static void print_usage(const char* argv0)
{
    fprintf(stderr,
        "DMADump — DMA-based process memory dumper (MemProcFS / PCILeech)\n"
        "\n"
        "Usage:\n"
        "  %s -device <device> [-pid <PID>] [-p <name_regex>] [-out <path>]\n"
        "       [-v] [-noimprec] [-hiddenonly] [-chunks] [-genheader]\n"
        "\n"
        "Options:\n"
        "  -device <device>    MemProcFS device string, e.g. 'fpga' or a .dmp file\n"
        "  -pid <PID>          Target PID (decimal or 0x-prefixed hex)\n"
        "  -p <regex>          Match process names with this regex (case-insensitive)\n"
        "  -out <path>         Output directory (default: current directory)\n"
        "  -v                  Verbose output\n"
        "  -noimprec           Disable import reconstruction\n"
        "  -hiddenonly         Only dump hidden/injected modules\n"
        "  -chunks             Also scan private executable memory for PE images\n"
        "  -genheader          Force synthetic PE header generation\n"
        "  -memmap <path>      MemProcFS memory map file (default: auto)\n"
        "\n"
        "Examples:\n"
        "  DMADump.exe -device fpga -pid 1234 -out C:\\dumps\n"
        "  DMADump.exe -device fpga -p lsass.exe -out C:\\dumps -v\n"
        "  DMADump.exe -device C:\\mem.dmp -pid 1234\n",
        argv0);
}

// -----------------------------------------------------------------------
// Enumerate all PIDs whose process name matches 'regex_str'
// -----------------------------------------------------------------------
static vector<DWORD> find_pids_by_name(VMM_HANDLE hVMM, const char* regex_str)
{
    vector<DWORD> result;

    DWORD* pPids  = nullptr;
    SIZE_T cPids  = 0;
    if (!VMMDLL_PidList(hVMM, nullptr, &cPids))
    {
        fprintf(stderr, "ERROR: VMMDLL_PidList (count) failed.\n");
        return result;
    }
    pPids = new DWORD[cPids];
    if (!VMMDLL_PidList(hVMM, pPids, &cPids))
    {
        fprintf(stderr, "ERROR: VMMDLL_PidList (fill) failed.\n");
        delete[] pPids;
        return result;
    }

    regex re(regex_str, regex_constants::icase);

    for (SIZE_T i = 0; i < cPids; i++)
    {
        VMMDLL_PROCESS_INFORMATION info = {};
        info.magic    = VMMDLL_PROCESS_INFORMATION_MAGIC;
        info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
        SIZE_T cb = sizeof(info);

        if (!VMMDLL_ProcessGetInformation(hVMM, pPids[i], &info, &cb))
            continue;

        const char* name = info.szNameLong[0] ? info.szNameLong : info.szName;
        if (regex_search(string(name), re))
            result.push_back(pPids[i]);
    }

    delete[] pPids;
    return result;
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main(int argc, char* argv[])
{

    // Hardcoded args for local debugger — remove before release
    const char* debug_argv[] = {
        argv[0],
        "-device",    "fpga",
        "-memmap",    "C:\\memory-maps\\physmemmap.txt",
        "-p",         "RuneLite.exe",
        "-out",       "dumped",
        "-hiddenonly",
    };
    argc = (int)(sizeof(debug_argv) / sizeof(debug_argv[0]));
    argv = (char**)debug_argv;


    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    // ---- Parse arguments ----
    const char* device_str = "fpga";
    const char* memmap_str = "auto";
    const char* out_path   = "";
    const char* name_regex = nullptr;
    DWORD       target_pid = 0;
    bool        pid_set    = false;
    PD_OPTIONS  opts;

    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "-device") == 0 && i + 1 < argc)
            device_str = argv[++i];
        else if (_stricmp(argv[i], "-memmap") == 0 && i + 1 < argc)
            memmap_str = argv[++i];
        else if (_stricmp(argv[i], "-pid") == 0 && i + 1 < argc)
        {
            const char* s = argv[++i];
            target_pid = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                       ? (DWORD) strtoul(s + 2, nullptr, 16)
                       : (DWORD) strtoul(s, nullptr, 10);
            pid_set = true;
        }
        else if (_stricmp(argv[i], "-p") == 0 && i + 1 < argc)
            name_regex = argv[++i];
        else if (_stricmp(argv[i], "-out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (_stricmp(argv[i], "-v") == 0)
            opts.Verbose = true;
        else if (_stricmp(argv[i], "-noimprec") == 0)
            opts.ImportRec = false;
        else if (_stricmp(argv[i], "-hiddenonly") == 0)
            opts.DumpHiddenOnly = true;
        else if (_stricmp(argv[i], "-chunks") == 0)
            opts.DumpChunks = true;
        else if (_stricmp(argv[i], "-genheader") == 0)
            opts.ForceGenHeader = true;
        else if (_stricmp(argv[i], "-help") == 0 || _stricmp(argv[i], "--help") == 0 || _stricmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!pid_set && !name_regex)
    {
        fprintf(stderr, "ERROR: Specify a target with -pid <PID> or -p <name_regex>.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    opts.set_output_path(out_path);

    // ---- Build MemProcFS argument list ----
    // VMMDLL_Initialize wants argv-style: ["-device", "<device>", "-memmap", "<map>", ...]
    vector<const char*> vmm_args;
    vmm_args.push_back("-device");
    vmm_args.push_back(device_str);
    vmm_args.push_back("-memmap");
    vmm_args.push_back(memmap_str);

    printf("Initialising MemProcFS with device '%s' memmap '%s'...\n", device_str, memmap_str);

    VMM_HANDLE hVMM = VMMDLL_Initialize((DWORD) vmm_args.size(),
                                        (LPCSTR*) vmm_args.data());
    if (!hVMM)
    {
        fprintf(stderr, "ERROR: VMMDLL_Initialize failed. "
                        "Make sure vmm.dll and leechcore.dll are next to this .exe and the device is accessible.\n");
        return 1;
    }
    printf("MemProcFS initialised.\n\n");

    // ---- Build hash database (no paths = empty, still needed for EP reconstruction) ----
    // Look for database files alongside the executable; skip gracefully if absent.
    char exe_dir[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe_dir, MAX_PATH);
    char* last_sep = strrchr(exe_dir, '\\');
    if (last_sep) *(last_sep + 1) = '\0'; else exe_dir[0] = '\0';

    char db_clean[MAX_PATH], db_ep[MAX_PATH], db_epshort[MAX_PATH];
    _snprintf(db_clean,   sizeof(db_clean)   - 1, "%spe_hash_db_clean.bin",   exe_dir);
    _snprintf(db_ep,      sizeof(db_ep)      - 1, "%spe_hash_db_ep.bin",      exe_dir);
    _snprintf(db_epshort, sizeof(db_epshort) - 1, "%spe_hash_db_epshort.bin", exe_dir);

    pe_hash_database* db = new pe_hash_database(db_clean, db_ep, db_epshort);

    // ---- Collect target PIDs ----
    vector<DWORD> targets;
    if (pid_set)
    {
        targets.push_back(target_pid);
    }
    if (name_regex)
    {
        printf("Searching for processes matching '%s'...\n", name_regex);
        vector<DWORD> matched = find_pids_by_name(hVMM, name_regex);
        if (matched.empty())
        {
            fprintf(stderr, "WARNING: No processes matched '%s'.\n", name_regex);
        }
        else
        {
            printf("Matched %zu process(es).\n", matched.size());
            for (DWORD pid : matched)
                targets.push_back(pid);
        }
    }

    // ---- Dump each target ----
    printf("\n");
    for (DWORD pid : targets)
    {
        dma_process proc(hVMM, pid, db, &opts);
        if (!proc.is_opened())
        {
            fprintf(stderr, "WARNING: Could not open PID 0x%x, skipping.\n", pid);
            continue;
        }
        printf("=== PID 0x%x (%s) ===\n", pid, proc.get_name());
        proc.dump_all();
        printf("\n");
    }

    // ---- Cleanup ----
    delete db;
    VMMDLL_Close(hVMM);
    printf("Done.\n");
    return 0;
}
