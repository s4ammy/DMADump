#pragma once

#include <windows.h>
#include <string.h>

// Options structure for DMADump.
// Named PD_OPTIONS to stay compatible with pe_header.cpp / pe_hash_database.cpp
// which reference this name directly.
class PD_OPTIONS
{
public:
    bool ImportRec;
    bool ForceGenHeader;
    bool Verbose;
    bool ReconstructHeaderAsDll;
    bool DumpChunks;            // also scan private executable memory for PE headers
    bool EntryPointHash;
    bool ForceReconstructEntryPoint;
    bool DumpHiddenOnly;        // only dump NOTLINKED/INJECTED modules
    int  NumberOfThreads;

    __int64  EntryPointOverride;
    char*    output_path;

    PD_OPTIONS()
    {
        ImportRec                = true;
        ForceGenHeader           = false;
        Verbose                  = false;
        ReconstructHeaderAsDll   = false;
        DumpChunks               = false;
        EntryPointHash           = false;
        ForceReconstructEntryPoint = false;
        DumpHiddenOnly           = false;
        NumberOfThreads          = 1;
        EntryPointOverride       = 0;
        output_path              = new char[1];
        output_path[0]           = '\0';
    }

    void set_output_path(const char* path)
    {
        if (output_path != nullptr)
            delete[] output_path;
        size_t len = strlen(path);
        output_path = new char[len + 1];
        memcpy(output_path, path, len + 1);
    }

    ~PD_OPTIONS()
    {
        if (output_path != nullptr)
            delete[] output_path;
    }
};

// Alias so dma_process.cpp can use either name
typedef PD_OPTIONS DMADUMP_OPTIONS;
