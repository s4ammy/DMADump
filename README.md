# DMADump

DMA-based process memory dumper built on [MemProcFS](https://github.com/ufrisk/MemProcFS) / PCILeech. Dumps PE images from live processes entirely through DMA — no `OpenProcess`, `ReadProcessMemory`, or `VirtualQueryEx` calls are made on the target machine.

Specialises in **hidden module detection**: manually mapped DLLs, reflectively injected code, and PE images absent from the PEB loader list.

---

## Requirements

- PCILeech-compatible DMA device (e.g. Squirrel, ScreamerM2, USB3380) **or** a raw memory dump file
- `vmm.dll`, `leechcore.dll` (and device-specific DLLs such as `FTD3XX.dll`) placed alongside `DMADump.exe`
- Windows x64 target

---

## Build

1. Open `DMADump.sln` in Visual Studio 2022
2. Select **Release | x64**
3. Build — output goes to `bin\Release\DMADump.exe`

Dependencies are in `Dependencies\MemProcFS\`. No external package manager needed.

---

## Usage

```
DMADump.exe -device <device> [-pid <PID>] [-p <name_regex>] [-out <path>]
            [-v] [-noimprec] [-hiddenonly] [-chunks] [-genheader]
            [-memmap <path>]
```

### Options

| Flag | Description |
|------|-------------|
| `-device <device>` | MemProcFS device string (`fpga`, path to `.dmp` file, etc.) |
| `-pid <PID>` | Target process by PID (decimal or `0x`-prefixed hex) |
| `-p <regex>` | Match processes by name (case-insensitive regex) |
| `-out <path>` | Output directory (default: current directory) |
| `-memmap <path>` | Physical memory map file (default: `auto`) |
| `-v` | Verbose output |
| `-noimprec` | Disable import reconstruction |
| `-hiddenonly` | Skip normally-loaded modules; only dump suspicious/hidden ones |
| `-chunks` | Also scan private executable memory for PE images (Tier 3) |
| `-genheader` | Force synthetic PE header generation for all targets |

---

## Examples

**Dump all modules from a process by name:**
```
DMADump.exe -device fpga -p notepad.exe -out C:\dumps
```

**Dump hidden/injected modules only from a specific PID:**
```
DMADump.exe -device fpga -pid 4512 -out C:\dumps -hiddenonly
```

**Dump from a process matching a regex, with verbose output:**
```
DMADump.exe -device fpga -p "chrome|firefox" -out C:\dumps -v
```

**Use a custom memory map (required on some FPGA setups):**
```
DMADump.exe -device fpga -memmap C:\memory-maps\physmemmap.txt -p lsass.exe -out C:\dumps
```

**Dump from a .dmp file instead of live DMA:**
```
DMADump.exe -device C:\captures\mem.dmp -pid 1234 -out C:\dumps
```

**Aggressive scan — include private executable pages (catches shellcode-embedded PEs):**
```
DMADump.exe -device fpga -p target.exe -out C:\dumps -hiddenonly -chunks -v
```

---

## Detection tiers

DMADump runs up to four detection passes per process:

| Tier | Method | Finds |
|------|--------|-------|
| **1** | `VMMDLL_Map_GetModuleU` — module type flags | `NOTLINKED` (PEB-hidden image maps), `INJECTED` (MemProcFS-identified injections) |
| **2** | VAD cross-reference — `fImage` entries absent from module map, no Windows system path | Reflectively injected DLLs mapped as image sections, deleted-on-disk payloads |
| **2b** | Private allocation scan — contiguous `fPrivateMemory` groups with executable sub-regions | Manually mapped DLLs (`VirtualAllocEx` + per-section `VirtualProtectEx`), erased-header maps |
| **3** | PTE map — non-NX private pages, MZ scan (`-chunks` only) | Shellcode-embedded PEs, runtime-decompressed payloads |

### Output filename format

```
<process>_PID<pid>_<module_name>_<base_address>_<tier_label>_<arch>.<ext>
```

Examples:
```
RuneLite_exe_PIDa3c_unknown_7FF812340000_NOTLINKED_x64.dll
target_exe_PID1a8_unknown_1A2B3C4D0000_MANUALMAP_NH_x64.dll
chrome_exe_PID9f0_ntdll_7FFEA0000000_VAD_HIDDEN_x64.dll
```

Tier labels: `NORMAL`, `NOTLINKED`, `INJECTED`, `DATA`, `VAD_HIDDEN`, `MANUALMAP`, `MANUALMAP_NH` (erased header), `MANUALMAP_EXEC`, `CHUNK`

---

## Hash database (optional)

DMADump can skip clean/known-good PE images using pre-built hash databases placed alongside the executable:

| File | Purpose |
|------|---------|
| `pe_hash_db_clean.bin` | Hashes of unmodified system DLLs — matched images are skipped |
| `pe_hash_db_ep.bin` | Entry-point hashes for import reconstruction |
| `pe_hash_db_epshort.bin` | Short entry-point hashes |

Without these files the tool still works; all PE images pass the hash check.

---

## Credits

- **[MemProcFS / PCILeech](https://github.com/ufrisk/MemProcFS)** by [@ufrisk](https://github.com/ufrisk) — DMA memory access, VAD/PTE maps, process enumeration
- **[Process Dump](https://github.com/glmcdona/Process-Dump)** by [@glmcdona](https://github.com/glmcdona) — PE parsing, import reconstruction, export list, hash database, and section processing code that this project builds on
- **[nmd](https://github.com/Nomade040/nmd)** by [@Nomade040](https://github.com/Nomade040) — embedded x86/x64 disassembler (`nmd_assembly.h`)
- **CLAUDE**