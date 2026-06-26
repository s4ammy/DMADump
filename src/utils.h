#pragma once

#include <windows.h>

// Bounds-check helper — returns true if [read_ptr, read_ptr+read_length) is within [buffer, buffer+length)
static bool test_read(unsigned char* buffer, SIZE_T length, unsigned char* read_ptr, SIZE_T read_length)
{
    return read_ptr >= buffer && read_ptr + read_length <= buffer + length;
}
