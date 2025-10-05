#include "ScannerCore.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cwctype>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
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

SCANNERCORE_API HANDLE OpenTargetProcess(DWORD processId)
{
    return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
}

SCANNERCORE_API BOOL CloseTargetProcess(HANDLE processHandle)
{
    if (processHandle == NULL || processHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    return CloseHandle(processHandle);
}

SCANNERCORE_API void FreeFoundAddresses(uintptr_t *addressesArray)
{
    if (addressesArray != nullptr)
    {
        delete[] addressesArray;
    }
}

SCANNERCORE_API void FreeFoundAddressesAndValues(void *resultsArray)
{
    if (resultsArray != nullptr)
    {
        delete[] static_cast<FoundResultWithValue *>(resultsArray);
    }
}

// Template functions
template <typename T>
BOOL ScanChunkNumericEx(
    HANDLE processHandle, uintptr_t startAddress, size_t chunkSizeToRead,
    T value1, T value2, ScanComparisonType comparisonType,
    FoundResultWithValue **foundResults, int *numFound)
{
    if (processHandle == NULL || foundResults == NULL || numFound == NULL)
    {
        if (numFound)
            *numFound = 0;
        if (foundResults)
            *foundResults = nullptr;
        return FALSE;
    }
    *numFound = 0;
    *foundResults = nullptr;
    if (chunkSizeToRead < sizeof(T))
        return TRUE;

    std::vector<BYTE> buffer(chunkSizeToRead);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(processHandle, (LPCVOID)startAddress, buffer.data(), chunkSizeToRead, &bytesRead))
    {
        return FALSE;
    }
    if (bytesRead < sizeof(T))
        return TRUE;

    std::vector<FoundResultWithValue> localFound;
    T v1 = value1, v2 = value2;
    if (comparisonType == ScanComparisonType::ValueBetween && value1 > value2)
    {
        std::swap(v1, v2);
    }

    for (size_t offset = 0; offset <= bytesRead - sizeof(T); offset += sizeof(T))
    {
        T valueInMemory = *(reinterpret_cast<T *>(buffer.data() + offset));
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

        if (match)
        {
            FoundResultWithValue res;
            res.address = startAddress + offset;
            if constexpr (std::is_same<T, int8_t>::value) {
    res.value.val_int8 = valueInMemory;
} else if constexpr (std::is_same<T, int16_t>::value) {
    res.value.val_int16 = valueInMemory;
} else if constexpr (std::is_same<T, int32_t>::value) {
    res.value.val_int32 = valueInMemory;
} else if constexpr (std::is_same<T, int64_t>::value) {
    res.value.val_int64 = valueInMemory;
} else if constexpr (std::is_same<T, float>::value) {
    res.value.val_float = valueInMemory;
} else if constexpr (std::is_same<T, double>::value) {
    res.value.val_double = valueInMemory;
}

            localFound.push_back(res);
        }
    }

    if (!localFound.empty())
    {
        *numFound = static_cast<int>(localFound.size());
        *foundResults = new FoundResultWithValue[localFound.size()];
        if (*foundResults == nullptr)
        {
            *numFound = 0;
            return FALSE;
        }
        memcpy(*foundResults, localFound.data(), localFound.size() * sizeof(FoundResultWithValue));
    }
    return TRUE;
}

// Exported numeric scan functions
SCANNERCORE_API BOOL ScanChunkForInt8Ex(HANDLE ph, uintptr_t addr, size_t size, int8_t v1, int8_t v2, ScanComparisonType ct,
                                        FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<int8_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt16Ex(HANDLE ph, uintptr_t addr, size_t size, int16_t v1, int16_t v2, ScanComparisonType ct,
                                         FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<int16_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt32Ex(HANDLE ph, uintptr_t addr, size_t size, int32_t v1, int32_t v2, ScanComparisonType ct,
                                         FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<int32_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForInt64Ex(HANDLE ph, uintptr_t addr, size_t size, int64_t v1, int64_t v2, ScanComparisonType ct,
                                         FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<int64_t>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForFloatEx(HANDLE ph, uintptr_t addr, size_t size, float v1, float v2, ScanComparisonType ct,
                                         FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<float>(ph, addr, size, v1, v2, ct, res, nFound);
}
SCANNERCORE_API BOOL ScanChunkForDoubleEx(HANDLE ph, uintptr_t addr, size_t size, double v1, double v2, ScanComparisonType ct,
                                          FoundResultWithValue **res, int *nFound)
{
    return ScanChunkNumericEx<double>(ph, addr, size, v1, v2, ct, res, nFound);
}

// String scanning
char to_lower_char(char c)
{
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

wchar_t to_lower_wchar(wchar_t c)
{
    return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
}

SCANNERCORE_API BOOL ScanChunkForStringA(
    HANDLE processHandle,
    uintptr_t startAddressOfPythonChunk,
    size_t totalSizeOfPythonChunk,
    const char *searchStrAnsi,
    BOOL caseSensitive,
    ScanComparisonType stringCompareType,
    uintptr_t **foundAddresses,
    int *numFound)
{
    if (!processHandle || !searchStrAnsi || !foundAddresses || !numFound)
    {
        if (numFound)
            *numFound = 0;
        if (foundAddresses)
            *foundAddresses = nullptr;
        return FALSE;
    }
    *numFound = 0;
    *foundAddresses = nullptr;

    size_t searchStrLen = strlen(searchStrAnsi);
    if (searchStrLen == 0 || totalSizeOfPythonChunk < searchStrLen)
        return TRUE;

    std::vector<uintptr_t> localFound;
    std::string search_s(searchStrAnsi);
    if (!caseSensitive)
    {
        std::transform(search_s.begin(), search_s.end(), search_s.begin(), to_lower_char);
    }

    const size_t INTERNAL_READ_SIZE = 4096;
    std::vector<BYTE> internal_buffer(INTERNAL_READ_SIZE);

    uintptr_t currentScanAddressInPythonChunk = startAddressOfPythonChunk;
    size_t remainingInPythonChunk = totalSizeOfPythonChunk;

    while (remainingInPythonChunk >= searchStrLen)
    {
        size_t bytesToReadForThisInternalChunk = min(INTERNAL_READ_SIZE, remainingInPythonChunk);
        if (bytesToReadForThisInternalChunk < searchStrLen)
            break;

        SIZE_T bytesActuallyRead = 0;
        if (!ReadProcessMemory(processHandle, (LPCVOID)currentScanAddressInPythonChunk, internal_buffer.data(), bytesToReadForThisInternalChunk,
                               &bytesActuallyRead))
        {
            break;
        }

        if (bytesActuallyRead < searchStrLen)
            break;

        for (size_t offsetInInternalChunk = 0; offsetInInternalChunk <= bytesActuallyRead - searchStrLen; ++offsetInInternalChunk)
        {
            bool match = false;
            if (caseSensitive)
            {
                if (memcmp(internal_buffer.data() + offsetInInternalChunk, search_s.data(), searchStrLen) == 0)
                {
                    match = true;
                }
            }
            else
            {
                bool current_char_match = true;
                for (size_t k = 0; k < searchStrLen; ++k)
                {
                    if (to_lower_char(static_cast<char>(internal_buffer[offsetInInternalChunk + k])) != search_s[k])
                    {
                        current_char_match = false;
                        break;
                    }
                }
                if (current_char_match)
                    match = true;
            }

            if (match)
            {
                localFound.push_back(currentScanAddressInPythonChunk + offsetInInternalChunk);
            }
        }

        if (bytesActuallyRead == 0)
            break;

        currentScanAddressInPythonChunk += bytesActuallyRead;
        remainingInPythonChunk = (currentScanAddressInPythonChunk < startAddressOfPythonChunk + totalSizeOfPythonChunk) ? (startAddressOfPythonChunk + totalSizeOfPythonChunk - currentScanAddressInPythonChunk) : 0;
    }

    if (!localFound.empty())
    {
        *numFound = static_cast<int>(localFound.size());
        *foundAddresses = new uintptr_t[localFound.size()];
        if (!(*foundAddresses))
        {
            *numFound = 0;
            return FALSE;
        }
        memcpy(*foundAddresses, localFound.data(), localFound.size() * sizeof(uintptr_t));
    }
    return TRUE;
}

SCANNERCORE_API BOOL ScanChunkForStringW(
    HANDLE processHandle,
    uintptr_t startAddressOfPythonChunk,
    size_t totalSizeOfPythonChunk,
    const wchar_t *searchStrWide,
    BOOL caseSensitive,
    ScanComparisonType stringCompareType,
    uintptr_t **foundAddresses,
    int *numFound)
{
    if (!processHandle || !searchStrWide || !foundAddresses || !numFound)
    {
        if (numFound)
            *numFound = 0;
        if (foundAddresses)
            *foundAddresses = nullptr;
        return FALSE;
    }
    *numFound = 0;
    *foundAddresses = nullptr;

    size_t searchStrCharLen = wcslen(searchStrWide);
    size_t searchStrByteLen = searchStrCharLen * sizeof(wchar_t);
    if (searchStrByteLen == 0 || totalSizeOfPythonChunk < searchStrByteLen)
        return TRUE;

    std::vector<uintptr_t> localFound;
    std::wstring search_ws(searchStrWide);
    if (!caseSensitive)
    {
        std::transform(search_ws.begin(), search_ws.end(), search_ws.begin(), to_lower_wchar);
    }

    const size_t INTERNAL_READ_SIZE = 4096;
    std::vector<BYTE> internal_buffer_bytes(INTERNAL_READ_SIZE);

    uintptr_t currentScanAddressInPythonChunk = startAddressOfPythonChunk;
    size_t remainingInPythonChunk = totalSizeOfPythonChunk;

    while (remainingInPythonChunk >= searchStrByteLen)
    {
        size_t bytesToReadForThisInternalChunk = min(INTERNAL_READ_SIZE, remainingInPythonChunk);
        if (bytesToReadForThisInternalChunk < searchStrByteLen)
            break;

        SIZE_T bytesActuallyRead = 0;
        if (!ReadProcessMemory(processHandle, (LPCVOID)currentScanAddressInPythonChunk, internal_buffer_bytes.data(), bytesToReadForThisInternalChunk,
                               &bytesActuallyRead))
        {
            break;
        }

        if (bytesActuallyRead < searchStrByteLen)
            break;

        const wchar_t *internal_buffer_wide = reinterpret_cast<const wchar_t *>(internal_buffer_bytes.data());
        size_t internal_buffer_wide_len = bytesActuallyRead / sizeof(wchar_t);

        for (size_t offset_in_wide_chars = 0; offset_in_wide_chars <= internal_buffer_wide_len - searchStrCharLen; ++offset_in_wide_chars)
        {
            bool match = false;
            if (caseSensitive)
            {
                if (wmemcmp(internal_buffer_wide + offset_in_wide_chars, search_ws.c_str(), searchStrCharLen) == 0)
                {
                    match = true;
                }
            }
            else
            {
                bool current_char_match = true;
                for (size_t k = 0; k < searchStrCharLen; ++k)
                {
                    if (to_lower_wchar(internal_buffer_wide[offset_in_wide_chars + k]) != search_ws[k])
                    {
                        current_char_match = false;
                        break;
                    }
                }
                if (current_char_match)
                    match = true;
            }

            if (match)
            {
                localFound.push_back(currentScanAddressInPythonChunk + (offset_in_wide_chars * sizeof(wchar_t)));
            }
        }

        if (bytesActuallyRead == 0)
            break;
        currentScanAddressInPythonChunk += bytesActuallyRead;
        remainingInPythonChunk = (currentScanAddressInPythonChunk < startAddressOfPythonChunk + totalSizeOfPythonChunk) ? (startAddressOfPythonChunk + totalSizeOfPythonChunk - currentScanAddressInPythonChunk) : 0;

        if (bytesActuallyRead < bytesToReadForThisInternalChunk)
            break;
    }

    if (!localFound.empty())
    {
        *numFound = static_cast<int>(localFound.size());
        *foundAddresses = new uintptr_t[localFound.size()];
        if (!(*foundAddresses))
        {
            *numFound = 0;
            return FALSE;
        }
        memcpy(*foundAddresses, localFound.data(), localFound.size() * sizeof(uintptr_t));
    }
    return TRUE;
}

SCANNERCORE_API BOOL ScanChunkForAoB(
    HANDLE processHandle,
    uintptr_t startAddressOfPythonChunk,
    size_t totalSizeOfPythonChunk,
    const BYTE *patternToSearch,
    size_t patternLength,
    uintptr_t **foundAddresses,
    int *numFound)
{
    if (!processHandle || !patternToSearch || patternLength == 0 || !foundAddresses || !numFound)
    {
        if (numFound)
            *numFound = 0;
        if (foundAddresses)
            *foundAddresses = nullptr;
        return FALSE;
    }
    *numFound = 0;
    *foundAddresses = nullptr;

    if (totalSizeOfPythonChunk < patternLength)
        return TRUE;

    std::vector<uintptr_t> localFound;

    const size_t INTERNAL_READ_SIZE = 4096 * 4;
    std::vector<BYTE> internal_buffer(INTERNAL_READ_SIZE);

    uintptr_t currentInternalReadStartAddr = startAddressOfPythonChunk;
    size_t bytesScannedSoFarInPythonChunk = 0;

    while (bytesScannedSoFarInPythonChunk < totalSizeOfPythonChunk)
    {

        size_t bytesToReadForThisInternalPass = min(INTERNAL_READ_SIZE, totalSizeOfPythonChunk - bytesScannedSoFarInPythonChunk);

        if (bytesToReadForThisInternalPass < patternLength)
        {
            break;
        }

        SIZE_T bytesSuccessfullyReadFromProcess = 0;
        if (!ReadProcessMemory(processHandle, (LPCVOID)currentInternalReadStartAddr, internal_buffer.data(), bytesToReadForThisInternalPass, &bytesSuccessfullyReadFromProcess))
        {

            break;
        }

        if (bytesSuccessfullyReadFromProcess < patternLength)
        {
            break;
        }

        for (size_t offsetInInternalChunk = 0; offsetInInternalChunk <= bytesSuccessfullyReadFromProcess - patternLength; ++offsetInInternalChunk)
        {
            if (memcmp(internal_buffer.data() + offsetInInternalChunk, patternToSearch, patternLength) == 0)
            {
                localFound.push_back(currentInternalReadStartAddr + offsetInInternalChunk);
            }
        }

        if (bytesSuccessfullyReadFromProcess == 0)
            break;

        size_t advanceAmount;
        if (patternLength > 1 && bytesSuccessfullyReadFromProcess >= patternLength)
        {
            advanceAmount = bytesSuccessfullyReadFromProcess - (patternLength - 1);
        }
        else
        {
            advanceAmount = bytesSuccessfullyReadFromProcess;
        }

        if (advanceAmount == 0)
            advanceAmount = 1;

        currentInternalReadStartAddr += advanceAmount;
        bytesScannedSoFarInPythonChunk += advanceAmount;

        if (bytesSuccessfullyReadFromProcess < bytesToReadForThisInternalPass)
        {
            break;
        }
    }

    if (!localFound.empty())
    {
        *numFound = static_cast<int>(localFound.size());
        *foundAddresses = new uintptr_t[localFound.size()];
        if (!(*foundAddresses))
        {
            *numFound = 0;
            return FALSE;
        }
        memcpy(*foundAddresses, localFound.data(), localFound.size() * sizeof(uintptr_t));
    }
    return TRUE;
}