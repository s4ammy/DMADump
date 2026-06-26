#include "pe_hash_database.h"

bool pe_hash_database::_is_mz(FILE* stream)
{
    char twochars[2];
    if ((fread(&twochars, 1, 2, stream) == 2) && twochars[0] == 'M' && twochars[1] == 'Z')
    {
        fseek(stream, 0, SEEK_SET);
        return true;
    }
    fseek(stream, 0, SEEK_SET);
    return false;
}

pe_hash_database::pe_hash_database(char* clean_database_name, char* ep_database_name, char* epshort_database_name)
{
    InitializeCriticalSectionAndSpinCount(&_lock, 0x00000400);
    EnterCriticalSection(&_lock);

    _clean_database_path = new char[strlen(clean_database_name) + 1];
    strcpy(_clean_database_path, clean_database_name);

    _ep_database_path = new char[strlen(ep_database_name) + 1];
    strcpy(_ep_database_path, ep_database_name);

    _epshort_database_path = new char[strlen(epshort_database_name) + 1];
    strcpy(_epshort_database_path, epshort_database_name);

    _clean_hashes.rehash(0x10000);
    _ep_hashes.rehash(0x10000);
    _epshort_hashes.rehash(0x10000);

    printf("Loading clean hash database from '%s'.\n", clean_database_name);
    FILE* fh = fopen(_clean_database_path, "rb");
    unsigned __int64 hash;
    if (fh)
    {
        while (!feof(fh))
        {
            if (fread(&hash, sizeof(unsigned __int64), 1, fh) == 1)
                _clean_hashes.insert(hash);
        }
        fclose(fh);
        printf("Loaded %zu clean hashes from database.\n", _clean_hashes.size());
    }
    else
    {
        if (PathFileExistsA(_clean_database_path))
        {
            fprintf(stderr, "ERROR: Failed to open existing hash database. Terminating.\n");
            exit(-1);
        }
        printf("Did not find an existing clean hash database, using an empty one.\n");
    }

    printf("Loading entrypoint hash database from '%s'.\n", ep_database_name);
    fh = fopen(_ep_database_path, "rb");
    if (fh)
    {
        while (!feof(fh))
        {
            if (fread(&hash, sizeof(unsigned __int64), 1, fh) == 1)
                _ep_hashes.insert(hash);
        }
        fclose(fh);
        printf("Loaded %zu entrypoint hashes from database.\n", _ep_hashes.size());
    }
    else
    {
        if (PathFileExistsA(_ep_database_path))
        {
            fprintf(stderr, "ERROR: Failed to open existing entrypoint hash database. Terminating.\n");
            exit(-1);
        }
        printf("Did not find an existing entrypoint hash database, using an empty one.\n");
    }

    printf("Loading entrypoint short hash database from '%s'.\n", epshort_database_name);
    fh = fopen(_epshort_database_path, "rb");
    if (fh)
    {
        while (!feof(fh))
        {
            if (fread(&hash, sizeof(unsigned __int64), 1, fh) == 1)
                _epshort_hashes.insert(hash);
        }
        fclose(fh);
        printf("Loaded %zu entrypoint short hashes from database.\n", _epshort_hashes.size());
    }
    else
    {
        if (PathFileExistsA(_epshort_database_path))
        {
            fprintf(stderr, "ERROR: Failed to open existing entrypoint short hash database. Terminating.\n");
            exit(-1);
        }
        printf("Did not find an existing entrypoint short hash database, using an empty one.\n");
    }

    LeaveCriticalSection(&_lock);
}

int pe_hash_database::count()
{
    EnterCriticalSection(&_lock);
    int result = (int) _clean_hashes.size();
    LeaveCriticalSection(&_lock);
    return result;
}

int pe_hash_database::count_eps()
{
    EnterCriticalSection(&_lock);
    int result = (int) _ep_hashes.size();
    LeaveCriticalSection(&_lock);
    return result;
}

int pe_hash_database::count_epshorts()
{
    EnterCriticalSection(&_lock);
    int result = (int) _epshort_hashes.size();
    LeaveCriticalSection(&_lock);
    return result;
}

bool pe_hash_database::clear_database()
{
    EnterCriticalSection(&_lock);
    _clean_hashes.clear();
    _ep_hashes.clear();
    _epshort_hashes.clear();
    LeaveCriticalSection(&_lock);
    return true;
}

bool pe_hash_database::add_hashes(unordered_set<unsigned __int64> hashes)
{
    EnterCriticalSection(&_lock);
    for (auto it = hashes.begin(); it != hashes.end(); it++)
    {
        if (*it != 0 && _clean_hashes.count(*it) == 0)
            _clean_hashes.insert(*it);
    }
    LeaveCriticalSection(&_lock);
    return true;
}

bool pe_hash_database::add_hashes_eps(unordered_set<unsigned __int64> hashes, unordered_set<unsigned __int64> hashes_short)
{
    EnterCriticalSection(&_lock);
    for (auto it = hashes.begin(); it != hashes.end(); it++)
    {
        if (*it != 0 && _ep_hashes.count(*it) == 0)
            _ep_hashes.insert(*it);
    }
    for (auto it = hashes_short.begin(); it != hashes_short.end(); it++)
    {
        if (*it != 0 && _epshort_hashes.count(*it) == 0)
            _epshort_hashes.insert(*it);
    }
    LeaveCriticalSection(&_lock);
    return true;
}

bool pe_hash_database::add_folder(char* dir_name, WCHAR* filter, bool recursively)
{
    char dir_name_expanded[MAX_PATH + 1];
    if (ExpandEnvironmentStringsA(dir_name, dir_name_expanded, MAX_PATH) < MAX_PATH)
    {
        DWORD ftyp = GetFileAttributesA(dir_name_expanded);
        if (ftyp != INVALID_FILE_ATTRIBUTES &&
            (ftyp & FILE_ATTRIBUTE_DIRECTORY) &&
            !(ftyp & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            DIR* dir;
            struct dirent* ent;
            dir = opendir(dir_name_expanded);
            if (dir != nullptr)
            {
                while ((ent = readdir(dir)) != nullptr)
                {
                    wchar_t* result = new wchar_t[strlen(ent->d_name) + 1];
                    if (result != nullptr)
                    {
                        for (int i = 0; i < (int) strlen(ent->d_name); i++)
                            result[i] = ent->d_name[i];
                        result[strlen(ent->d_name)] = 0;

                        if (ent->d_type & DT_DIR)
                        {
                            if (recursively && wcscmp(result, L".") != 0 && wcscmp(result, L"..") != 0)
                            {
                                char* directory = new char[strlen(dir_name_expanded) + strlen(ent->d_name) + 2];
                                sprintf_s(directory, strlen(dir_name_expanded) + strlen(ent->d_name) + 2,
                                    "%s\\%s", dir_name_expanded, ent->d_name);
                                add_folder(directory, filter, recursively);
                                delete[] directory;
                            }
                        }
                        else
                        {
                            if (PathMatchSpec(result, filter))
                            {
                                int length = (int)(wcslen(result) + strlen(dir_name_expanded) + 1);
                                char* filename = new char[length + 1];
                                filename[length] = 0;
                                sprintf(filename, "%s\\%S", dir_name_expanded, result);

                                FILE* fh = fopen(filename, "rb");
                                if (fh != nullptr)
                                {
                                    if (_is_mz(fh)) { fclose(fh); add_file(filename); }
                                    else fclose(fh);
                                }
                                else
                                    fprintf(stderr, "Error opening file %s: %s.\n", filename, strerror(errno));
                                delete[] filename;
                            }
                        }
                        delete[] result;
                    }
                    else
                        fprintf(stderr, "Failed to allocate memory for filename.\n");
                }
                closedir(dir);
                return true;
            }
            else
                fprintf(stderr, "Unable to open directory %s: %s.\n", dir_name_expanded, strerror(errno));
        }
    }
    return false;
}

bool pe_hash_database::remove_folder(char* dir_name, WCHAR* filter, bool recursively)
{
    char dir_name_expanded[MAX_PATH + 1];
    ExpandEnvironmentStringsA(dir_name, dir_name_expanded, MAX_PATH);

    DIR* dir;
    struct dirent* ent;
    dir = opendir(dir_name_expanded);
    if (dir != nullptr)
    {
        while ((ent = readdir(dir)) != nullptr)
        {
            wchar_t* result = new wchar_t[strlen(ent->d_name) + 1];
            if (result != nullptr)
            {
                for (int i = 0; i < (int) strlen(ent->d_name); i++)
                    result[i] = ent->d_name[i];
                result[strlen(ent->d_name)] = 0;

                if (ent->d_type & DT_DIR)
                {
                    if (recursively && wcscmp(result, L".") != 0 && wcscmp(result, L"..") != 0)
                    {
                        char* directory = new char[strlen(dir_name_expanded) + strlen(ent->d_name) + 2];
                        sprintf(directory, "%s/%s", dir_name_expanded, ent->d_name);
                        remove_folder(directory, filter, recursively);
                        delete[] directory;
                    }
                }
                else
                {
                    if (PathMatchSpec(result, filter))
                    {
                        int length = (int)(wcslen(result) + strlen(dir_name_expanded) + 1);
                        char* filename = new char[length + 1];
                        filename[length] = 0;
                        sprintf(filename, "%s\\%S", dir_name_expanded, result);

                        FILE* fh = fopen(filename, "rb");
                        if (fh != nullptr)
                        {
                            if (_is_mz(fh)) { fclose(fh); remove_file(filename); }
                            else fclose(fh);
                        }
                        else
                            fprintf(stderr, "Error opening file %s: %s.\n", filename, strerror(errno));
                        delete[] filename;
                    }
                }
                delete[] result;
            }
            else
                fprintf(stderr, "Failed to allocate memory for filename.\n");
        }
        closedir(dir);
        return true;
    }
    else
        fprintf(stderr, "Unable to open directory %s: %s.\n", dir_name_expanded, strerror(errno));
    return false;
}

bool pe_hash_database::contains(unsigned __int64 hash)
{
    return _clean_hashes.count(hash) != 0;
}

bool pe_hash_database::contains_ep(unsigned __int64 hash)
{
    return _ep_hashes.count(hash) != 0;
}

bool pe_hash_database::contains_epshort(unsigned __int64 hash)
{
    return _epshort_hashes.count(hash) != 0;
}

bool pe_hash_database::add_file(char* file)
{
    PD_OPTIONS options;
    options.ForceGenHeader = false;
    options.ImportRec      = false;
    options.Verbose        = false;
    options.EntryPointHash = true;
    pe_header* header = new pe_header(file, &options);
    header->process_pe_header();
    header->process_sections();

    if (!header->somewhat_parsed())
    {
        printf("Failed to parse PE header for %s.\n", file);
        delete header;
        return false;
    }

    unsigned __int64 hash         = header->get_hash();
    unsigned __int64 hash_ep      = header->get_hash_ep();
    unsigned __int64 hash_ep_short = header->get_hash_ep_short();
    delete header;

    if (hash_ep != 0)
    {
        EnterCriticalSection(&_lock);
        if (_ep_hashes.count(hash_ep) == 0)
        {
            _ep_hashes.insert(hash_ep);
            printf("...new entrypoint hash %s,0x%llX\n", file, hash_ep);
        }
        LeaveCriticalSection(&_lock);
    }

    if (hash_ep_short != 0)
    {
        EnterCriticalSection(&_lock);
        if (_epshort_hashes.count(hash_ep_short) == 0)
        {
            _epshort_hashes.insert(hash_ep_short);
            printf("...new entrypoint short hash %s,0x%llX\n", file, hash_ep_short);
        }
        LeaveCriticalSection(&_lock);
    }

    if (hash != 0)
    {
        EnterCriticalSection(&_lock);
        if (_clean_hashes.count(hash) == 0)
        {
            _clean_hashes.insert(hash);
            printf("...new hash %s,0x%llX\n", file, hash);
        }
        LeaveCriticalSection(&_lock);
        return true;
    }

    printf("Failed to calculate hash for file %s.\n", file);
    return false;
}

bool pe_hash_database::remove_file(char* file)
{
    PD_OPTIONS options;
    options.ForceGenHeader = false;
    options.ImportRec      = false;
    options.Verbose        = false;
    options.EntryPointHash = false;
    pe_header* header = new pe_header(file, &options);
    header->process_pe_header();
    header->process_sections();

    unsigned __int64 hash = 0;
    if (header->somewhat_parsed())
        hash = header->get_hash();
    delete header;

    if (hash != 0)
    {
        EnterCriticalSection(&_lock);
        if (_clean_hashes.count(hash) != 0)
        {
            _clean_hashes.erase(hash);
            printf("...deleted hash %s,0x%llX\n", file, hash);
        }
        LeaveCriticalSection(&_lock);
        return true;
    }

    printf("Failed to add hash for file %s.\n", file);
    return false;
}

bool pe_hash_database::save()
{
    FILE* fh;
    unsigned __int64 hash;

    fh = fopen(_ep_database_path, "wb");
    if (fh)
    {
        EnterCriticalSection(&_lock);
        for (auto it = _ep_hashes.begin(); it != _ep_hashes.end(); ++it)
        {
            hash = *it;
            fwrite(&hash, sizeof(unsigned __int64), 1, fh);
        }
        fclose(fh);
        LeaveCriticalSection(&_lock);
        printf("Wrote to entrypoint hash database. It now has a total of %zu entrypoint hashes.\n", _ep_hashes.size());
    }
    else
        fprintf(stderr, "ERROR: Failed to open existing entrypoint database for writing.\n");

    fh = fopen(_epshort_database_path, "wb");
    if (fh)
    {
        EnterCriticalSection(&_lock);
        for (auto it = _epshort_hashes.begin(); it != _epshort_hashes.end(); ++it)
        {
            hash = *it;
            fwrite(&hash, sizeof(unsigned __int64), 1, fh);
        }
        fclose(fh);
        LeaveCriticalSection(&_lock);
        printf("Wrote to entrypoint short hash database. It now has a total of %zu entrypoint short hashes.\n", _epshort_hashes.size());
    }
    else
        fprintf(stderr, "ERROR: Failed to open existing entrypoint short hash database for writing.\n");

    fh = fopen(_clean_database_path, "wb");
    if (fh)
    {
        EnterCriticalSection(&_lock);
        for (auto it = _clean_hashes.begin(); it != _clean_hashes.end(); ++it)
        {
            hash = *it;
            fwrite(&hash, sizeof(unsigned __int64), 1, fh);
        }
        fclose(fh);
        LeaveCriticalSection(&_lock);
        printf("Wrote to clean hash database. It now has a total of %zu clean hashes.\n", _clean_hashes.size());
        return true;
    }
    else
        fprintf(stderr, "ERROR: Failed to open existing clean hash database for writing.\n");

    return false;
}

pe_hash_database::~pe_hash_database(void)
{
    delete[] _clean_database_path;
    delete[] _ep_database_path;
    delete[] _epshort_database_path;
    DeleteCriticalSection(&_lock);
}
