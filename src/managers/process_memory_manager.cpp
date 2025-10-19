#define NOMINMAX

#include "process_memory_manager.h"
#include "../gui/status_ui.h" // For logging - TODO: Replace with dedicated logger interface
#include "../hack/hack.h"
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>
#include <string>
#include <windows.h>
#include <algorithm>
#include <cstdint>

/**
 * WStringToString - Converts a wide string (std::wstring) to a UTF-8 encoded string (std::string).
 * @wstr: The wide string to convert.
 * Returns: The converted UTF-8 string.
 */
std::string WStringToString(const std::wstring& wstr)
{
    if (wstr.empty())
        return (std::string());

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    if (size_needed <= 0)
        return (std::string()); // Error

    std::string strTo(size_needed, 0);
    int bytes_converted = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    if (bytes_converted <= 0)
        return (std::string()); // Error

    return (strTo);
}


/**
 * PMM_to_hex_string - Converts an address to a hexadecimal string representation.
 * @address: The address to convert.
 * Returns: The hexadecimal string representation of the address.
 */
std::string PMM_to_hex_string(uintptr_t address)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << address;
    return (oss.str());
}

/**
 * ProcessMemoryManager Constructor
 */
ProcessMemoryManager::~ProcessMemoryManager()
{
    Detach();
}

/**
 * Attach - Attaches to a process by its name.
 * @processName: The name of the process to attach to (wide string).
 * Returns: True if attachment was successful, false otherwise.
 */
bool ProcessMemoryManager::Attach(const wchar_t* processName)
{
    if (IsAttached())
        // LogStatus("INFO: Already attached to process ID: " + std::to_string(m_processId));
        return (true); // Already attached is not an error

    m_processId = FindProcessId(processName);
    if (m_processId == 0)
    {
        LogError("Attach failed: Process not found: " + WStringToString(processName), false);
        return (false);
    }

    // Using PROCESS_ALL_ACCESS for simplicity; consider least privilege if needed.
    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
    if (m_processHandle == nullptr)
    {
        LogError("Attach failed: OpenProcess failed for PID: " + std::to_string(m_processId));
        m_processId = 0;
        return (false);
    }

    LogStatus("INFO: Successfully attached to process ID: " + std::to_string(m_processId));
    return (true);
}

/**
 * Detach - Detaches from the currently attached process.
 */
void ProcessMemoryManager::Detach()
{
    if (m_processHandle != nullptr && m_processHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_processHandle);
        LogStatus("INFO: Detached from process ID: " + std::to_string(m_processId));
    }
    m_processHandle = nullptr;
    m_processId = 0;
}

/**
 * IsAttached - Checks if currently attached to a process.
 * Returns: True if attached, false otherwise.
 */
bool ProcessMemoryManager::IsAttached() const
{
    // Basic check; does not guarantee the process is still responsive.
    return (m_processHandle != nullptr && m_processHandle != INVALID_HANDLE_VALUE);
}

/**
 * ResolvePointerChain - Resolves a multi-level pointer chain to get the final address.
 * @baseAddress: The base address to start from.
 * @offsets: A vector of offsets to traverse the pointer chain.
 * Returns: The final resolved address, or 0 on error.
 */
uintptr_t ProcessMemoryManager::ResolvePointerChain(uintptr_t baseAddress, const std::vector<unsigned int>& offsets) const
{
    if (!IsAttached())
        // LogError("ResolvePointerChain failed: Process not attached."); // Potentially spammy
        return (0);

    uintptr_t currentAddress = baseAddress;
    for (size_t i = 0; i < offsets.size(); ++i)
    {
        if (!Read<uintptr_t>(currentAddress, currentAddress))
        {
            LogError("ResolvePointerChain failed: Read error at level " + std::to_string(i) + " (address " + PMM_to_hex_string(currentAddress) + ")");
            return (0);
        }
        // Depending on target, null pointers in the chain might be an error.
        if (currentAddress == 0)
        {
            LogError("ResolvePointerChain failed: Null pointer encountered at level " + std::to_string(i));
            return (0);
        }
        currentAddress += offsets[i];
    }
    return (currentAddress);
}

/**
 * ScanPatternModule - Scans a module for a byte pattern with a mask.
 * @moduleName: The name of the module to scan (wide string).
 * @pattern: The byte pattern to search for.
 * @mask: The mask string where 'x' means match and '?' means ignore.
 * Returns: The address of the found pattern, or 0 if not found/error.
 */
uintptr_t ProcessMemoryManager::ScanPatternModule(const wchar_t* moduleName, const char* pattern, const char* mask) const
{
    if (!IsAttached())
        return (0);

    MODULEENTRY32 moduleInfo = GetModuleInfo(moduleName);
    if (moduleInfo.th32ModuleID == 0)
    {
        LogError("ScanPatternModule failed: Module not found: " + WStringToString(moduleName), false);
        return (0);
    }

    uintptr_t begin = reinterpret_cast<uintptr_t>(moduleInfo.modBaseAddr);
    uintptr_t end = begin + moduleInfo.modBaseSize;

    return (ScanPatternRange(begin, end, pattern, mask));
}

/**
 * ScanPatternRange - Scans a memory range for a byte pattern with a mask.
 * @begin: The starting address of the range to scan.
 * @end: The ending address of the range to scan.
 * @pattern: The byte pattern to search for.
 * @mask: The mask string where 'x' means match and '?' means ignore.
 * Returns: The address of the found pattern, or 0 if not found/error.
 */
uintptr_t ProcessMemoryManager::ScanPatternRange(uintptr_t begin, uintptr_t end, const char* pattern, const char* mask) const
{
    if (!IsAttached() || begin >= end)
        return (0); // Basic validation

    size_t patternLength = strlen(mask);
    if (patternLength == 0)
        return (0);

    const size_t chunkSize = 4096;
    std::vector<char> buffer(chunkSize);
    uintptr_t currentChunkBase = begin;

    while (currentChunkBase < end)
    {
        uint64_t remainingBytes = static_cast<uint64_t>(end - currentChunkBase);
        uint64_t readAmount = std::min(static_cast<uint64_t>(chunkSize), remainingBytes); // Use std::min directly
        SIZE_T bytesToRead = static_cast<SIZE_T>(readAmount);

        if (bytesToRead == 0)
            break;

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(currentChunkBase), buffer.data(), bytesToRead, &bytesRead))
        {
            // Failed to read this chunk (e.g., PAGE_NOACCESS); log and skip to the next potential chunk.
            // LogError("ScanPatternRange info: ReadProcessMemory failed for chunk at " + PMM_to_hex_string(currentChunkBase) + ". Skipping chunk.", true); // Optional detailed logging
            currentChunkBase += bytesToRead;
            continue;
        }

        if (bytesRead == 0)
            // Read succeeded but returned 0 bytes? Unusual, stop scanning.
            // LogError("ScanPatternRange warning: Read 0 bytes successfully at " + PMM_to_hex_string(currentChunkBase) + ", stopping scan.", false); // Optional detailed logging
            break;

        // Scan the buffer content that was actually read.
        const char* foundInternal = ScanPatternInternal(buffer.data(), bytesRead, pattern, mask);

        if (foundInternal != nullptr)
        {
            // Found the pattern; calculate address in the target process.
            uintptr_t offsetInBuffer = static_cast<uintptr_t>(foundInternal - buffer.data());
            return (currentChunkBase + offsetInBuffer);
        }

        // Pattern not found in this chunk, advance. Overlap scan regions to handle patterns spanning chunks.
        if (bytesRead > (patternLength - 1))
            currentChunkBase += (bytesRead - (patternLength - 1));
        else
            // Chunk smaller than pattern; advance fully to prevent infinite loops.
            currentChunkBase += bytesRead;

        // Optimization: Stop if remaining memory is smaller than the pattern.
        if (currentChunkBase >= end || (end - currentChunkBase) < patternLength)
            break;
    }

    return (0); // Pattern not found in the specified range
}

/**
 * Nop - Replaces a block of memory with NOP instructions.
 * @address: The starting address to NOP.
 * @size: The number of bytes to replace with NOPs.
 * Returns: True if successful, false otherwise.
 */
bool ProcessMemoryManager::Nop(uintptr_t address, size_t size) const
{
    if (!IsAttached() || size == 0)
        return (false);

    std::vector<std::byte> nopArray(size);
    memset(nopArray.data(), 0x90, size); // x86 NOP instruction

    return (Patch(address, nopArray.data(), size));
}

/**
 * Patch - Writes raw data to a specified memory address.
 * @address: The address to write to.
 * @data: Pointer to the data to write.
 * @size: The number of bytes to write.
 * Returns: True if successful, false otherwise.
 */
bool ProcessMemoryManager::Patch(uintptr_t address, const void* data, size_t size) const {
    if (!IsAttached() || data == nullptr || size == 0)
        return (false);

    DWORD oldProtect = 0;
    // Temporarily change protection to allow writing to executable memory.
    if (!VirtualProtectEx(m_processHandle, reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        LogError("Patch failed: VirtualProtectEx (pre-write) failed at address " + PMM_to_hex_string(address));
        return (false);
    }

    SIZE_T bytesWritten = 0;
    bool success = WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), data, size, &bytesWritten);

    if (!success)
        LogError("Patch failed: WriteProcessMemory failed at address " + PMM_to_hex_string(address));

    // Attempt to restore original protection regardless of write success.
    DWORD tempProtect;
    if (!VirtualProtectEx(m_processHandle, reinterpret_cast<LPVOID>(address), size, oldProtect, &tempProtect))
        LogError("Patch warning: VirtualProtectEx (post-write restore) failed at address " + PMM_to_hex_string(address));
        // Write might have succeeded, but protection restore failed. Consider this a partial failure?

    return (success && (bytesWritten == size));
}


// --- Private Helper Implementations ---

/**
 * FindProcessId - Finds the process ID of a process by its name.
 * @processName: The name of the process to find (wide string).
 * Returns: The process ID if found, or 0 if not found/error.
 */
DWORD ProcessMemoryManager::FindProcessId(const wchar_t* processName) const {
    PROCESSENTRY32 procEntry = { sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        // LogError("FindProcessId failed: CreateToolhelp32Snapshot failed.");
        return (0);
    // RAII wrapper for snapshot handle recommended for production code
    // struct SnapshotHandle { HANDLE h; ~SnapshotHandle() { if(h != INVALID_HANDLE_VALUE) CloseHandle(h); } } snapshot { hSnapshot };

    DWORD pid = 0;
    if (Process32FirstW(hSnapshot, &procEntry))
    {
        do {
            if (wcscmp(procEntry.szExeFile, processName) == 0)
            {
                pid = procEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &procEntry));
    }
    else
        // LogError("FindProcessId failed: Process32FirstW failed.");

    CloseHandle(hSnapshot);
    return (pid);
}

/**
 * GetModuleInfo - Retrieves information about a module in the attached process.
 * @moduleName: The name of the module to retrieve (wide string).
 * Returns: A MODULEENTRY32 structure with module info, or with th32ModuleID set to 0 on failure.
 */
MODULEENTRY32 ProcessMemoryManager::GetModuleInfo(const wchar_t* moduleName) const
{
    MODULEENTRY32 modEntry = { sizeof(MODULEENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_processId);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        // LogError("GetModuleInfo failed: CreateToolhelp32Snapshot failed for PID: " + std::to_string(m_processId));
        modEntry.th32ModuleID = 0;
        return (modEntry);
    }

    bool found = false;
    if (Module32FirstW(hSnapshot, &modEntry))
    {
        do {
            if (wcscmp(modEntry.szModule, moduleName) == 0)
            {
                found = true;
                break;
            }
        } while (Module32NextW(hSnapshot, &modEntry));
    }
    else
        // LogError("GetModuleInfo failed: Module32FirstW failed for PID: " + std::to_string(m_processId));

    CloseHandle(hSnapshot);
    if (!found)
        modEntry.th32ModuleID = 0; // Ensure failure indication if not found
    return (modEntry);
}

/**
 * ScanPatternInternal - Scans a memory block for a byte pattern with a mask.
 * @base: Pointer to the start of the memory block.
 * @size: Size of the memory block in bytes.
 * @pattern: The byte pattern to search for.
 * @mask: The mask string where 'x' means match and '?' means ignore.
 * Returns: Pointer to the found pattern within the block, or nullptr if not found.
 */
const char* ProcessMemoryManager::ScanPatternInternal(const char* base, size_t size, const char* pattern, const char* mask) const
{
    size_t patternLength = strlen(mask);
    if (patternLength == 0 || size < patternLength)
        return (nullptr);

    for (size_t i = 0; i <= size - patternLength; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patternLength; ++j)
        {
            if (mask[j] != '?' && pattern[j] != *(base + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
            return (base + i);
    }
    return (nullptr);
}

// --- Logging Wrappers ---

/**
 * LogStatus - Logs a status message.
 * @message: The message to log.
 */
void ProcessMemoryManager::LogStatus(const std::string& message) const
{
    // TODO: Replace with a call to a dedicated logger if created
    StatusUI::AddMessage(message);
}

/**
 * LogError - Logs an error message, optionally including the last Windows error.
 * @message: The error message to log.
 * @includeWinError: Whether to append the last Windows error message.
 */
void ProcessMemoryManager::LogError(const std::string& message, bool includeWinError) const
{
    std::string fullMessage = "ERROR (PMM): " + message;
    if (includeWinError)
    {
        DWORD errorCode = GetLastError();
        if (errorCode != 0)
        {
            LPSTR messageBuffer = nullptr;
            // Use FORMAT_MESSAGE_IGNORE_INSERTS for safety
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

            if (messageBuffer)
            {
                std::string winError(messageBuffer, size);
                LocalFree(messageBuffer);
                // Trim trailing whitespace/newlines
                while (!winError.empty() && isspace(static_cast<unsigned char>(winError.back())))
                    winError.pop_back();
                fullMessage += " (WinError " + std::to_string(errorCode) + ": " + winError + ")";
            }
            else
                fullMessage += " (WinError " + std::to_string(errorCode) + ": Failed to format message)";
        }
        // Optional: else { fullMessage += " (No Windows error code)"; }
    }
    // TODO: Replace with a call to a dedicated logger if created
    StatusUI::AddMessage(fullMessage);
}

/**
 * GetMainWindowHandle - Retrieves the main window handle of the attached process.
 * @hwnd: The handle to the main window, or nullptr if not found.
 * @lParam: The target process ID.
 * Returns: TRUE to continue enumeration, FALSE to stop.
 */
static BOOL CALLBACK PMM_EnumWindowsProcFindByPid(HWND hwnd, LPARAM lParam)
{
    DWORD windowPid = 0;
    ::GetWindowThreadProcessId(hwnd, &windowPid);
    DWORD targetPid = static_cast<DWORD>(lParam);

    if (windowPid == targetPid)
    {
        if (::IsWindowVisible(hwnd) && (::GetWindow(hwnd, GW_OWNER) == nullptr))
        {
            ::SetProp(hwnd, L"__PMM_MAINWND__", (HANDLE)1);
            return (FALSE);
        }
    }
    return (TRUE);
}

/**
 * GetMainWindowHandle - Retrieves the main window handle of the attached process.
 * Returns: The handle to the main window, or nullptr if not found.
 */
HWND ProcessMemoryManager::GetMainWindowHandle()
{
    if (!IsAttached())
        return (nullptr);

    if (m_cachedMainWindow && ::IsWindow(m_cachedMainWindow))
        return (m_cachedMainWindow);

    // Clear any previous marks
    ::EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
        if (::GetProp(hwnd, L"__PMM_MAINWND__"))
            ::RemoveProp(hwnd, L"__PMM_MAINWND__");
        return (TRUE);
    }, 0);

    ::EnumWindows(PMM_EnumWindowsProcFindByPid, (LPARAM)m_processId);

    HWND result = nullptr;
    ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (::GetProp(hwnd, L"__PMM_MAINWND__"))
        {
            *reinterpret_cast<HWND*>(lParam) = hwnd;
            ::RemoveProp(hwnd, L"__PMM_MAINWND__");
            return (FALSE);
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&result));

    m_cachedMainWindow = result;
    return (m_cachedMainWindow);
}

/**
 * PostVirtualKeyHold - Holds a key for the specified duration using SendInput.
 * @vk: Virtual-key code to send.
 * @holdMilliseconds: Duration to hold before releasing.
 * Returns: True if both down and up events were sent.
 */
bool ProcessMemoryManager::PostVirtualKeyHold(WORD vk, DWORD holdMilliseconds)
{
    if (!IsAttached())
        return false;

    HWND target = GetMainWindowHandle();
    if (!target)
        return false;

    UINT scan = ::MapVirtualKey(vk, MAPVK_VK_TO_VSC);
    auto isExtendedKey = [](WORD v) -> bool {
        switch (v)
        {
        case VK_LEFT: case VK_RIGHT: case VK_UP: case VK_DOWN:
        case VK_INSERT: case VK_DELETE: case VK_HOME: case VK_END:
        case VK_PRIOR: case VK_NEXT: case VK_RCONTROL: case VK_RMENU:
        case VK_SNAPSHOT: case VK_DIVIDE: case VK_LWIN: case VK_RWIN:
        case VK_APPS:
            return true;
        default:
            return false;
        }
        };
    DWORD extBit = isExtendedKey(vk) ? (1u << 24) : 0u;
    LPARAM lParamDown = (1) | (static_cast<LPARAM>(scan) << 16) | extBit;
    LPARAM lParamUp = (1) | (static_cast<LPARAM>(scan) << 16) | extBit | (1 << 30) | (1u << 31);

    BOOL ok1 = ::PostMessage(target, WM_KEYDOWN, vk, lParamDown);
    if (!ok1) return false;
    ::Sleep(holdMilliseconds);
    BOOL ok2 = ::PostMessage(target, WM_KEYUP, vk, lParamUp);
    return (ok2 != FALSE);
}