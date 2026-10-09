#include "memory_scanner.h"

#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>

#if !defined(_M_X64) && !defined(__x86_64__)
#error Memory Integrity Inspector requires an x64 target.
#endif

Classification ClassifyRegion(const MEMORY_BASIC_INFORMATION& region) noexcept {
    if (region.State != MEM_COMMIT) {
        return Classification::None;
    }

    const DWORD baseProtection = region.Protect & 0xFFu;
    switch (baseProtection) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        return Classification::None;
    }

    if (baseProtection == PAGE_EXECUTE_READWRITE) {
        return Classification::Suspicious;
    }
    if (region.Type == MEM_IMAGE) {
        return Classification::Info;
    }
    return Classification::Review;
}

std::string FormatProtection(DWORD protection) {
    if (protection == 0) {
        return "Unavailable (0x00000000)";
    }

    std::ostringstream output;
    switch (protection & 0xFFu) {
    case PAGE_NOACCESS: output << "PAGE_NOACCESS"; break;
    case PAGE_READONLY: output << "PAGE_READONLY"; break;
    case PAGE_READWRITE: output << "PAGE_READWRITE"; break;
    case PAGE_WRITECOPY: output << "PAGE_WRITECOPY"; break;
    case PAGE_EXECUTE: output << "PAGE_EXECUTE"; break;
    case PAGE_EXECUTE_READ: output << "PAGE_EXECUTE_READ"; break;
    case PAGE_EXECUTE_READWRITE: output << "PAGE_EXECUTE_READWRITE"; break;
    case PAGE_EXECUTE_WRITECOPY: output << "PAGE_EXECUTE_WRITECOPY"; break;
    default: output << "UNKNOWN_BASE"; break;
    }

    if ((protection & PAGE_GUARD) != 0) {
        output << " | PAGE_GUARD";
    }
    if ((protection & PAGE_NOCACHE) != 0) {
        output << " | PAGE_NOCACHE";
    }
    if ((protection & PAGE_WRITECOMBINE) != 0) {
        output << " | PAGE_WRITECOMBINE";
    }
    if ((protection & PAGE_TARGETS_INVALID) != 0) {
        output << " | PAGE_TARGETS_INVALID/NO_UPDATE";
    }

    const DWORD knownBits = 0xFFu | PAGE_GUARD | PAGE_NOCACHE |
                            PAGE_WRITECOMBINE | PAGE_TARGETS_INVALID;
    if ((protection & ~knownBits) != 0) {
        output << " | OTHER_MODIFIERS";
    }
    output << " (0x" << std::hex << std::uppercase << std::setw(8)
           << std::setfill('0') << protection << ')';
    return output.str();
}

const char* FormatMemoryType(DWORD type) noexcept {
    switch (type) {
    case MEM_IMAGE: return "MEM_IMAGE";
    case MEM_MAPPED: return "MEM_MAPPED";
    case MEM_PRIVATE: return "MEM_PRIVATE";
    default: return "UNKNOWN";
    }
}

ScanResult InspectProcess(DWORD processId, bool retainFindings) {
    ScanResult result;
    const auto stop = [&result](const char* detail, DWORD error) {
        result.status = result.regionsQueried == 0 ? ScanStatus::Failed : ScanStatus::Partial;
        result.detail = detail;
        result.error = error;
    };

    std::unique_ptr<void, decltype(&CloseHandle)> process(
        OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, processId), &CloseHandle);
    if (!process) {
        stop("Cannot open target; it may be inaccessible, protected, or no longer running.",
             GetLastError());
        return result;
    }

    const auto targetIsRunning = [&]() {
        const DWORD waitResult = WaitForSingleObject(process.get(), 0);
        if (waitResult == WAIT_TIMEOUT) {
            return true;
        }
        if (waitResult == WAIT_OBJECT_0) {
            stop("Target process terminated; inspection is incomplete.", ERROR_SUCCESS);
        } else {
            const DWORD error = waitResult == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
            stop("Cannot verify target process lifetime; inspection is incomplete.", error);
        }
        return false;
    };

    if (!targetIsRunning()) {
        return result;
    }

    BOOL isWow64 = FALSE;
    if (!IsWow64Process(process.get(), &isWow64)) {
        stop("Cannot determine target architecture.", GetLastError());
        return result;
    }
    if (isWow64) {
        stop("Only native x64 target processes are supported; target is a WOW64 process.",
             ERROR_NOT_SUPPORTED);
        return result;
    }

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    if (systemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        stop("This utility requires Windows running on x64 hardware.", ERROR_NOT_SUPPORTED);
        return result;
    }

    const auto maximumAddress = reinterpret_cast<std::uintptr_t>(
        systemInfo.lpMaximumApplicationAddress);
    std::uintptr_t address = 0;

    while (address <= maximumAddress) {
        if (!targetIsRunning()) {
            return result;
        }

        MEMORY_BASIC_INFORMATION region{};
        const SIZE_T returnedBytes = VirtualQueryEx(process.get(),
            reinterpret_cast<LPCVOID>(address), &region, sizeof(region));
        if (returnedBytes != sizeof(region)) {
            const DWORD error = returnedBytes == 0 ? GetLastError() : ERROR_BAD_LENGTH;
            stop("VirtualQueryEx did not return a complete region; inspection stopped.", error);
            return result;
        }

        const auto baseAddress = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        if (region.RegionSize == 0 || baseAddress != address ||
            region.RegionSize > std::numeric_limits<std::uintptr_t>::max() - baseAddress) {
            stop("Invalid or changing region boundaries; safe traversal could not continue.",
                 ERROR_INVALID_DATA);
            return result;
        }
        const std::uintptr_t nextAddress = baseAddress + region.RegionSize;
        if (nextAddress <= address) {
            stop("Region traversal did not advance; inspection stopped.", ERROR_INVALID_DATA);
            return result;
        }
        ++result.regionsQueried;

        if (region.State == MEM_COMMIT) {
            if (region.RegionSize > std::numeric_limits<std::uint64_t>::max() -
                                    result.committedBytes) {
                stop("Committed memory statistics would overflow; inspection stopped.",
                     ERROR_ARITHMETIC_OVERFLOW);
                return result;
            }
            ++result.committedRegions;
            result.committedBytes += region.RegionSize;
            const Classification classification = ClassifyRegion(region);
            if (classification != Classification::None) {
                switch (region.Type) {
                case MEM_IMAGE: ++result.executableImageRegions; break;
                case MEM_MAPPED: ++result.executableMappedRegions; break;
                case MEM_PRIVATE: ++result.executablePrivateRegions; break;
                default: ++result.executableOtherRegions; break;
                }
                switch (classification) {
                case Classification::Info: ++result.infoFindings; break;
                case Classification::Review: ++result.reviewFindings; break;
                case Classification::Suspicious: ++result.suspiciousFindings; break;
                default: break;
                }
                if (retainFindings) {
                    result.findings.push_back({region, classification});
                }
            }
        }
        address = nextAddress;
    }

    if (targetIsRunning()) {
        result.status = ScanStatus::Completed;
        result.detail = "Address-space traversal completed; observations are not an atomic snapshot.";
    }
    return result;
}
