#pragma once 

#include <windows.h>
#include <cstdint>
#include <string>

#ifdef SCANNERCORE_EXPORTS
#define SCANNERCORE_API __declspec(dllexport)
#else 
#define SCANNERCORE_API __declspec(dllimport)
#endif

enum class ScanComparisonType: int {
    ExactValue = 0,
    ValueBetween = 1,
    BiggerThan = 2,
    SmallerThan = 3,
    StringContains = 4,
    StringExact = 5,
    AoBExact = 6
};

extern "C" {
    SCANNERCORE_API HANDLE OpenTargetProcess(DWORD processId);
    SCANNERCORE_API BOOL CloseTargetProcess(HANDLE processHandle);
    SCANNERCORE_API void FreeFoundAddresses(uintptr_t* addressesArray);
    SCANNERCORE_API void FreeFoundAddressesAndValues(void* resultsArray);

    struct FoundResultWithValue
    {
        uintptr_t address;
        union 
        {
            int8_t val_int8;
            int16_t val_int16;
            int32_t val_int32;
            int64_t val_int64;
            float val_float;
            double val_double;
        } value;
    };

    // Specialized Scan Functions
    SCANNERCORE_API BOOL ScanChunkForInt8Ex(HANDLE ph, uintptr_t addr, size_t size, int8_t v1, int8_t v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForInt16Ex(HANDLE ph, uintptr_t addr, size_t size, int16_t v1, int16_t v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForInt32Ex(HANDLE ph, uintptr_t addr, size_t size, int32_t v1, int32_t v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForInt64Ex(HANDLE ph, uintptr_t addr, size_t size, int64_t v1, int64_t v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForFloatEx(HANDLE ph, uintptr_t addr, size_t size, float v1, float v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForDoubleEx(HANDLE ph, uintptr_t addr, size_t size, double v1, double v2,
    ScanComparisonType ct, FoundResultWithValue** res, int* nFound);
    
    // String Scanning
    SCANNERCORE_API BOOL ScanChunkForStringA(HANDLE ph, uintptr_t addr, size_t size, const char* searchStr, BOOL 
        caseSensitive, ScanComparisonType stringCompareType, uintptr_t** found, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForStringW(HANDLE ph, uintptr_t addr, size_t size, const wchar_t* searchStr, BOOL 
        caseSensitive, ScanComparisonType stringCompareType, uintptr_t** found, int* nFound);
    SCANNERCORE_API BOOL ScanChunkForStringAoB(HANDLE ph, uintptr_t addr, size_t size, const BYTE* pattern, size_t 
        patternLen, uintptr_t** found, int* nFound);
}