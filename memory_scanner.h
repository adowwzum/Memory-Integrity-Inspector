#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

enum class Classification { None, Info, Review, Suspicious };
enum class ScanStatus { Failed, Partial, Completed };

struct MemoryFinding {
    MEMORY_BASIC_INFORMATION region{};
    Classification classification = Classification::None;
};

struct ScanResult {
    ScanStatus status = ScanStatus::Failed;
    std::string detail;
    DWORD error = ERROR_SUCCESS;
    std::uint64_t regionsQueried = 0;
    std::uint64_t committedRegions = 0;
    std::uint64_t committedBytes = 0;
    std::uint64_t executableImageRegions = 0;
    std::uint64_t executableMappedRegions = 0;
    std::uint64_t executablePrivateRegions = 0;
    std::uint64_t executableOtherRegions = 0;
    std::uint64_t infoFindings = 0;
    std::uint64_t reviewFindings = 0;
    std::uint64_t suspiciousFindings = 0;
    std::vector<MemoryFinding> findings;
};

Classification ClassifyRegion(const MEMORY_BASIC_INFORMATION& region) noexcept;
std::string FormatProtection(DWORD protection);
const char* FormatMemoryType(DWORD type) noexcept;
ScanResult InspectProcess(DWORD processId, bool retainFindings);
