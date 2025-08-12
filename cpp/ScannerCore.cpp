#include "ScannerCore.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cwtype>

BOOL APIENTRY DllMain(HModule hModule,
DWORD ul_reason_for_call,
LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

SCANNERCORE_API HANDLE OpenTargetProcess(DWORD processId) {
    return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId); 
}

SCANNERCORE_API BOOL CloseTargetProcess(HANDLE processHandle) {
    if (processHandle == NULL || processHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    return CloseHandle(processHandle);
}

SCANNERCORE_API void FreeFoundAddresses(uintptr_t* addressesArray) {
    if (addressesArray != nullptr) {
        delete[] addressesArray;
    }
}

SCANNERCORE_API void FreeFoundAddessesAndValues(void* resultsArray) {
    if (resultsArray != nullpt) {
        delete[] static_cast<FoundResultWithValue*>(resultsArray);
    }
}

// Template functions
template<typename T>
BOOL ScanChunkNumericEx(
    HANDLE processHandle, uintptr_t startAddress, size_t chunkSizeToRead,
    T value1, T value2, ScanComparisonType comparisonType,
    FoundResultWithValue** foundResults, int* numFound
)
{
    if (processHandle == NULL || foundResults == NULL || numFound == NULL) {
        if (numFound) *numFound = 0;
        if (foundResults) *foundResults = nullptr;
        return FALSE;
    }
    *numFound = 0;
    *foundResults = nullptr;
    if (chunkSizeToRead < sizeof(T)) return TRUE;

    std::vector<BYTE> buffer(chunkSizeToRead);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(processHandle, (LPCVOID)startAddress, buffer.data(), chunkSizeToRead, &bytesRead)) {
        return FALSE;
    }
    if (bytesRead < sizeof(T)) return TRUE;

    std::vector<FoundResultWithValue> localFound;
    T v1 = value1, v2 = value2;
    if (comparisonType == ScanComparisonType::ValueBetween && value1 > value2) {
        std::swap(v1, v2);
    }

    for (size_t offset = 0; offset <= bytesRead - sizeof(T); offset += sizeof(T)) {
        T valueInMemory = *(reinterpret_cast<T*>(buffer.data() + offset));
        bool match = false;
        switch (comparisonType)
        {
        case ScanComparisonType::ExactValue: 
            match = (valueInMemory == v1); 
            break;
        case ScanComparisonType::ValueBetween: 
            match = (valueInMemory >= v1 && valueInMemory <= v2); 
            break;
        case ScanComparisonType::BiggerThan:
            match = (valueInMemory > v1);
            break;
        case ScanComparisonType::SmallerThan:
            match = (valueInMemory < v1);
            break;
        default:
            break;
        }

        if (match) {
            FoundResultWithValue res;
            res.address = startAddress + offset;
            if constexpr(std::is_same<T, int8_t>) res.value.val_int8 = valueInMemory;
            else if constexpr(std::is_same<T, int16_t>) res.value.val_int16 = valueInMemory;
            else if constexpr(std::is_same<T, int32_t>) res.value.val_int32 = valueInMemory;
            else if constexpr(std::is_same<T, int64_t>) res.value.val_int64 = valueInMemory;
            else if constexpr(std::is_same<T, float>) res.value.val_float = valueInMemory;
            else if constexpr(std::is_same<T, double>) res.value.val_double = valueInMemory;
            localFound.push_back(res);
        }
    }

    if (!localFound.empty()) {
        *numFound = static_cast<int>(localFound.size());
        *foundResults = new FoundResultWithValue[localFound.size()];
        if (*foundResults == nullptr) { *numFound = 0; return FALSE; }
        memcpy(*foundResults, localFound.data(), localFound.size() * sizeof(FoundResultWithValue));
    }
    return TRUE;
}

// Exported numeric scan functions
SCANNERCORE_API BOOL ScanChunkForInt8Ex(HANDLE ph, uintptr_t addr, size_t, size, int8_t v1, int8_t v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<int8_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt16Ex(HANDLE ph, uintptr_t addr, size_t, size, int16_t v1, int16_t v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<int16_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt32Ex(HANDLE ph, uintptr_t addr, size_t, size, int32_t v1, int32_t v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<int32_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt64Ex(HANDLE ph, uintptr_t addr, size_t, size, int64_t v1, int64_t v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<int64_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForFloatEx(HANDLE ph, uintptr_t addr, size_t, size, float v1, float v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<float>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForDoubleEx(HANDLE ph, uintptr_t addr, size_t, size, double v1, double v2, ScanComparisonType ct,
FoundResultWithValue** res, int* nFound) {
    return ScanChunkNumericEx<double>(ph, addr, size, v1, v2, ct, res, nFound);
}