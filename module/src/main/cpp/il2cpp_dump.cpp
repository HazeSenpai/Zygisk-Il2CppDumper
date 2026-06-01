//
// Modified for raw libil2cpp.so + global-metadata.dat dumping.
// Skips dump.cs generation. Output drops both files into
//   <app_data_dir>/files/libil2cpp.so
//   <app_data_dir>/files/global-metadata.dat
//

#include "il2cpp_dump.h"
#include "log.h"

#include <cstdint>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

// Kept as a no-op stub — hack.cpp still calls this. We don't need the
// IL2CPP API resolved because we're doing raw memory dumping.
void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_api_init: raw-dump mode (handle=%p)", handle);
}

// ============================================================
// libil2cpp.so dumper
// Walks /proc/self/maps, collects every region whose path
// contains "libil2cpp.so", concatenates them into one memory
// image (file offset == VA - base). Use SoFixer afterwards
// with the printed base address to make IDA happy.
// ============================================================
static bool dump_libil2cpp_so(const std::string &out_path) {
    std::ifstream maps("/proc/self/maps");
    if (!maps) { LOGE("cannot open /proc/self/maps"); return false; }

    struct Region { uintptr_t start; uintptr_t end; char perms[5]; };
    std::vector<Region> regions;
    std::string line;

    while (std::getline(maps, line)) {
        if (line.find("libil2cpp.so") == std::string::npos) continue;
        Region r{};
        if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s", &r.start, &r.end, r.perms) < 3) continue;
        if (r.perms[0] != 'r') continue;  // need readable
        regions.push_back(r);
    }
    if (regions.empty()) { LOGE("libil2cpp.so not in /proc/self/maps"); return false; }

    uintptr_t base = regions[0].start;
    uintptr_t end  = regions[0].end;
    for (auto &r : regions) {
        if (r.start < base) base = r.start;
        if (r.end   > end ) end  = r.end;
    }
    size_t total = end - base;
    LOGI("libil2cpp.so: base=0x%" PRIxPTR " end=0x%" PRIxPTR " size=%zu regions=%zu",
         base, end, total, regions.size());
    LOGI(">>>>>>>>>> use this BASE in SoFixer: 0x%" PRIxPTR " <<<<<<<<<<", base);

    FILE *f = fopen(out_path.c_str(), "wb");
    if (!f) { LOGE("cannot open %s", out_path.c_str()); return false; }

    // Chunked, fault-tolerant write. Pad unmapped gaps with zeros so
    // file offset stays aligned with (VA - base).
    constexpr size_t CHUNK = 4096;
    std::vector<uint8_t> zeros(CHUNK, 0);
    for (uintptr_t addr = base; addr < end; addr += CHUNK) {
        size_t n = std::min(CHUNK, (size_t)(end - addr));
        bool mapped = false;
        for (auto &r : regions) {
            if (addr >= r.start && addr < r.end) { mapped = true; break; }
        }
        if (mapped) {
            fwrite(reinterpret_cast<const void*>(addr), 1, n, f);
        } else {
            fwrite(zeros.data(), 1, n, f);
        }
    }
    fclose(f);
    LOGI("libil2cpp.so -> %s (%zu bytes)", out_path.c_str(), total);
    return true;
}

// ============================================================
// global-metadata.dat dumper
// Scans all readable memory for the magic 0xFAB11BAF.
// Reads the Il2CppGlobalMetadataHeader's (offset, size) pairs
// to compute the exact file size, then dumps that range.
// ============================================================
constexpr uint32_t IL2CPP_METADATA_MAGIC = 0xFAB11BAF;

static size_t compute_metadata_size(const uint8_t *header, size_t region_size) {
    auto *arr = reinterpret_cast<const int32_t*>(header);
    // Walk (offset, size) pairs starting after sanity + version.
    // Header is at most ~256 bytes across all known IL2CPP versions.
    size_t pair_count = std::min((size_t)64, region_size / 8);
    size_t max_end = 16;
    for (size_t i = 2; i + 1 < pair_count * 2; i += 2) {
        int32_t off  = arr[i];
        int32_t sz   = arr[i + 1];
        if (off > 0 && sz > 0 && (size_t)(off + sz) <= region_size) {
            size_t e = (size_t)off + (size_t)sz;
            if (e > max_end) max_end = e;
        }
    }
    return max_end;
}

static bool dump_global_metadata(const std::string &out_path) {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return false;
    std::string line;

    while (std::getline(maps, line)) {
        uintptr_t s, e;
        char perms[5] = {0};
        if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %4s", &s, &e, perms) < 3) continue;
        if (perms[0] != 'r') continue;

        size_t region_size = e - s;
        if (region_size < 0x10000)    continue;  // metadata is >= 64KB
        if (region_size > 0x10000000) continue;  // skip mappings > 256MB

        // Read first 4 bytes — region was confirmed readable so memcpy is safe
        uint32_t magic = 0;
        memcpy(&magic, reinterpret_cast<void*>(s), sizeof(magic));
        if (magic != IL2CPP_METADATA_MAGIC) continue;

        auto *hdr = reinterpret_cast<const uint8_t*>(s);
        size_t size = compute_metadata_size(hdr, region_size);
        if (size == 0 || size > region_size) {
            LOGW("metadata header found but size invalid (computed=%zu region=%zu)",
                 size, region_size);
            size = region_size;
        }
        LOGI("global-metadata @ 0x%" PRIxPTR " size=%zu (region=%zu)", s, size, region_size);

        FILE *f = fopen(out_path.c_str(), "wb");
        if (!f) { LOGE("cannot open %s", out_path.c_str()); return false; }
        fwrite(reinterpret_cast<const void*>(s), 1, size, f);
        fclose(f);
        LOGI("global-metadata.dat -> %s", out_path.c_str());
        return true;
    }
    LOGE("no region matched IL2CPP magic 0xFAB11BAF");
    return false;
}

// ============================================================
// Entry point called from hack.cpp
// ============================================================
void il2cpp_dump(const char *outDir) {
    LOGI("===== RAW DUMP MODE =====");
    LOGI("outDir = %s", outDir);

    std::string files_dir = std::string(outDir) + "/files";
    mkdir(files_dir.c_str(), 0755);

    bool ok_so   = dump_libil2cpp_so   (files_dir + "/libil2cpp.so");
    bool ok_meta = dump_global_metadata(files_dir + "/global-metadata.dat");

    LOGI("===== DUMP COMPLETE  libil2cpp.so=%d  global-metadata.dat=%d =====",
         ok_so, ok_meta);
}
