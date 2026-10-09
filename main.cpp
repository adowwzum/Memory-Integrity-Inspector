#include "memory_scanner.h"

#include <charconv>
#include <exception>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <system_error>

namespace {

constexpr const char* Border = "============================================================";

void PrintBanner() {
    std::cout << Border << "\n"
              << "                 MEMORY INTEGRITY INSPECTOR\n"
              << "                   Windows x64 Research\n"
              << Border << "\n\n";
}

void PrintHelp() {
    PrintBanner();
    std::cout << "Usage:\n"
              << "  Memory-Integrity-Inspector.exe --help\n"
              << "  Memory-Integrity-Inspector.exe --pid <PID> [--summary]\n\n"
              << "  --help       Show usage; must be used alone.\n"
              << "  --pid        Inspect one native x64 process; decimal PID > 0.\n"
              << "  --summary    Show statistics and finding counts only.\n\n"
              << "Read-only metadata inspection. No elevation or memory reads.\n"
              << "INFO, REVIEW, and SUSPICIOUS describe memory properties.\n"
              << "Findings alone do not establish malware or cheating.\n\n"
              << "Exit codes: 0 completed/help, 1 failed, 2 usage, 3 partial.\n";
}

const char* ClassificationName(Classification classification) {
    switch (classification) {
    case Classification::Info: return "INFO";
    case Classification::Review: return "REVIEW";
    case Classification::Suspicious: return "SUSPICIOUS";
    default: return "NONE";
    }
}

const char* FindingTitle(const MemoryFinding& finding) {
    if (finding.classification == Classification::Suspicious) {
        return "Writable + Executable Memory";
    }
    switch (finding.region.Type) {
    case MEM_PRIVATE: return "Private Executable Memory";
    case MEM_MAPPED: return "Mapped Executable Memory";
    case MEM_IMAGE: return "Image Executable Memory";
    default: return "Executable Memory with Unknown Type";
    }
}

void PrintFinding(const MemoryFinding& finding) {
    const auto& region = finding.region;
    std::cout << '[' << ClassificationName(finding.classification) << "] "
              << FindingTitle(finding) << '\n'
              << "Address             : 0x" << std::hex << std::uppercase
              << std::setw(16) << std::setfill('0')
              << reinterpret_cast<std::uintptr_t>(region.BaseAddress)
              << std::dec << std::setfill(' ') << '\n'
              << "Region Size         : " << region.RegionSize << " bytes\n"
              << "State               : MEM_COMMIT\n"
              << "Protection          : " << FormatProtection(region.Protect) << '\n'
              << "Allocation Protect  : " << FormatProtection(region.AllocationProtect) << '\n'
              << "Memory Type         : " << FormatMemoryType(region.Type) << '\n';

    if (finding.classification == Classification::Suspicious) {
        std::cout << "Reason              : Current base protection permits read/write/execute.\n";
        if (region.Type == MEM_PRIVATE) {
            std::cout << "Also Observed       : Executable MEM_PRIVATE region.\n";
        }
    } else {
        switch (region.Type) {
        case MEM_IMAGE:
            std::cout << "Reason              : Executable image mapping; informational context.\n";
            break;
        case MEM_MAPPED:
            std::cout << "Reason              : Executable mapped memory; review its origin.\n";
            break;
        case MEM_PRIVATE:
            std::cout << "Reason              : Executable private allocation; review its origin.\n";
            break;
        default:
            std::cout << "Reason              : Executable region with unrecognized mapping type.\n";
            break;
        }
    }
    if ((region.Protect & 0xFFu) == PAGE_EXECUTE_WRITECOPY) {
        std::cout << "Copy-on-write       : Executable; not classified as direct RWX.\n";
    }
    if ((region.Protect & PAGE_GUARD) != 0) {
        std::cout << "Guard Modifier      : One-shot access alarm; base permissions classified.\n";
    }
    std::cout << '\n';
}

int Run(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        PrintHelp();
        return 0;
    }

    DWORD processId = 0;
    bool hasProcessId = false;
    bool summaryOnly = false;
    const auto usageError = [](const char* message) {
        std::cerr << "Error: " << message << "\n"
                  << "Usage: Memory-Integrity-Inspector.exe --pid <PID> [--summary]\n"
                  << "Use --help for details.\n";
        return 2;
    };

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--pid") {
            if (hasProcessId || index + 1 >= argc) {
                return usageError("--pid requires one value and may appear only once.");
            }
            const std::string_view value(argv[++index]);
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                                processId, 10);
            if (value.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != value.data() + value.size() || processId == 0) {
                return usageError("PID must be a nonzero decimal 32-bit unsigned integer.");
            }
            hasProcessId = true;
        } else if (argument == "--summary") {
            if (summaryOnly) {
                return usageError("--summary may appear only once.");
            }
            summaryOnly = true;
        } else {
            return usageError("Unknown option or invalid --help combination.");
        }
    }
    if (!hasProcessId) {
        return usageError("A target process ID is required.");
    }

    PrintBanner();
    std::cout << "Target PID          : " << processId << '\n'
              << "Status              : Inspecting process memory\n\n";
    const ScanResult result = InspectProcess(processId, !summaryOnly);
    for (const auto& finding : result.findings) {
        PrintFinding(finding);
    }

    const char* status = result.status == ScanStatus::Completed ? "Completed" :
                         result.status == ScanStatus::Partial ? "Partial" : "Failed";
    std::cout << "------------------------------------------------------------\n"
              << "Regions Queried     : " << result.regionsQueried << '\n'
              << "Regions Inspected   : " << result.committedRegions << " committed\n"
              << "Committed Bytes     : " << result.committedBytes << '\n'
              << "Executable IMAGE    : " << result.executableImageRegions << '\n'
              << "Executable MAPPED   : " << result.executableMappedRegions << '\n'
              << "Executable PRIVATE  : " << result.executablePrivateRegions << '\n'
              << "Executable OTHER    : " << result.executableOtherRegions << '\n'
              << "Info Findings       : " << result.infoFindings << '\n'
              << "Review Findings     : " << result.reviewFindings << '\n'
              << "Suspicious Findings : " << result.suspiciousFindings << '\n'
              << "Status              : " << status << '\n'
              << "Detail              : " << result.detail << '\n';
    if (result.error != ERROR_SUCCESS) {
        std::cout << "Windows Error       : " << result.error << '\n';
    }
    std::cout << "\nFindings describe memory properties, not proof of malware or cheating.\n"
              << Border << '\n';
    return result.status == ScanStatus::Completed ? 0 :
           result.status == ScanStatus::Partial ? 3 : 1;
}

}

int main(int argc, char* argv[]) {
    try {
        return Run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "Status: Failed. Inspection could not finish: " << error.what() << '\n';
    } catch (...) {
        std::cerr << "Status: Failed. Inspection could not finish due to an unexpected error.\n";
    }
    return 1;
}
