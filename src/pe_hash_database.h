#pragma once

// windows.h MUST come before dirent.h.
// dirent.h defines WIN32_LEAN_AND_MEAN which causes windows.h to skip
// wincrypt.h -> bcrypt.h, the only place NTSTATUS is typedef'd in this SDK.
// Including windows.h first (without that flag) makes NTSTATUS available for
// vmmdll.h which is pulled in transitively through pe_header.h -> dma_stream.h.
#include <windows.h>
#include <unordered_set>
#include <iostream>
#include <stdio.h>
#include <io.h>
#include <sys/types.h>
#include "dirent.h"
#include "Shlwapi.h"
#include "pe_header.h"
#include "options.h"
#include <windows.h>

using namespace std;

class pe_hash_database
{
    char* _clean_database_path;
    char* _ep_database_path;
    char* _epshort_database_path;

    unordered_set<unsigned __int64> _clean_hashes;
    unordered_set<unsigned __int64> _ep_hashes;
    unordered_set<unsigned __int64> _epshort_hashes;

    bool _is_mz(FILE* stream);
    CRITICAL_SECTION _lock;

public:
    pe_hash_database(char* clean_database_name, char* ep_database_name, char* epshort_database_name);

    int count();
    int count_eps();
    int count_epshorts();

    bool clear_database();

    bool add_hashes(unordered_set<unsigned __int64> hashes);
    bool add_hashes_eps(unordered_set<unsigned __int64> hashes, unordered_set<unsigned __int64> hashes_short);

    bool add_folder(char* dir_name, WCHAR* filter, bool recursively);
    bool remove_folder(char* dir_name, WCHAR* filter, bool recursively);
    bool contains(unsigned __int64 hash);
    bool contains_epshort(unsigned __int64 hash);
    bool contains_ep(unsigned __int64 hash);
    bool add_file(char* file);
    bool remove_file(char* file);
    bool save();
    ~pe_hash_database(void);
};
