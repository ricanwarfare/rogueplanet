# RoguePlanet

Windows Defender LPE exploit by Nightmare-Eclipse.

**For authorized security research and cyber exercises only.**

## Overview

The RoguePlanet exploit abuses a race condition in Windows Defender's scanning/remediation path to achieve SYSTEM shell from a standard user context. It does not rely on browser, driver, or memory corruption exploits — it races Defender's own cleanup operations.

Tested on Windows 10, Windows 11 (Official + Canary) with June 2026 patch installed.

## Server Variant (This Branch)

The `server` branch adds Windows Server support. On Windows Server, standard users cannot mount ISO images via `AttachVirtualDisk`, which the original exploit requires. This branch implements a two-pronged fallback:

### 1. VHD Mount (`MountVHD`)
Creates and attaches a dynamic VHDX. Works on Server configurations where:
- Hyper-V role is installed
- User has `SeVirtualDiskPrivilege`

### 2. System Device Path (`GetSystemDevicePath`)
Fallback when no virtual disk can be mounted. Enumerates `\Device\HarddiskVolume*` using `NtOpenDirectoryObject` (standard users CAN do this) and finds an accessible NTFS system volume.

The read-only ISO semantics are replicated by setting a restrictive DACL on the EICAR file that denies `DELETE` and `GENERIC_WRITE` — forcing Defender into the same remediation fallback path.

### How It Works

```
ISO mount fails → Try MountVHD() → Try GetSystemDevicePath() → Use g_devicepath
                                                      ↓
                                          WriteEicar with NULL isomnt
                                          → Writes EICAR directly
                                          → Sets read-only DACL
```

### Detection Differences (Server variant)

- `\Device\` directory enumeration via `NtOpenDirectoryObject`
- DACL manipulation on EICAR files
- No `\Device\CdRom*` path (uses `\Device\HarddiskVolume*` instead)
- All original signals remain: Defender scan, VSS, junctions, oplocks, QueueReporting

## Building

```bash
# MSVC
cl /EHsc /std:c++17 RoguePlanet.cpp /link kernel32.lib bcrypt.lib taskschd.lib comsupp.lib virtdisk.lib ntdll.lib Rpcrt4.lib shlwapi.lib

# MinGW
g++ -o RoguePlanet.exe RoguePlanet.cpp -lkernel32 -lbcrypt -ltaskschd -lcomsupp -lvirtdisk -lntdll -lRpcrt4 -lshlwapi
```

## Files

- `RoguePlanet.cpp` — Full source with Server modifications merged in
- `RoguePlanetServer.cpp` — Standalone Server variant (new functions only, for reference)
- `CHANGES.md` — Detailed diff from original

## Bug Fixes (server branch, 2026-06-13)

The initial merge had several bugs causing immediate crash on Windows Server:

1. **Missing ADS stream**: When `isomnt==NULL` (system device path fallback), `WriteEicar` skipped creating the `:WDFOO` alternate data stream. The VSS oplock path opens `wermgr.exe:WDFOO` — without this stream, `NtCreateFile` fails silently and the exploit race breaks. **Fixed**: Added WDFOO ADS creation to the `isomnt==NULL` branch.

2. **Stale `eicar_data` / double WriteEicar crash**: `WriteEicar` is called twice in `main()`. The second call hit the `if (eicar_data && eicar_sz)` early-return, which used `== ERROR_IO_PENDING` as an error check (inverted logic — synchronous writes return `TRUE`, not `ERROR_IO_PENDING`). This returned NULL, causing `CloseHandle(NULL)` → crash. **Fixed**: Added `eicar_written` guard; fixed the overlapped I/O check to handle synchronous completion correctly.

3. **DACL applied via path-based API on NT path**: `SetFileSecurityW(eicarpath, ...)` was called with an NT-format path (`\??\%TEMP%\...`). Win32 APIs don't handle `\??\` prefix, so the DACL was never applied — Defender could just delete the EICAR file, collapsing the race window. **Fixed**: Changed to `SetSecurityInfo(hfile, ...)` which operates on the open handle, not the path.

4. **Lock path wrong for system device fallback**: The lock path used `\Device\HarddiskVolumeN\wermgr.exe` which doesn't exist as a real file — in the system device case, the EICAR is written to the user's temp directory, not the device root. **Fixed**: Lock path now uses `maindirname\wermgr.exe` which resolves through the junction to the correct file regardless of mount method.

5. **GetSystemDevicePath enumeration failure**: NT `\Device` directory enumeration + `NtCreateFile` on each `HarddiskVolume*` fails from standard user tokens on Server 2025. **Fixed**: Added `QueryDosDeviceW` fallback that resolves `%SystemDrive%` to its NT device path via symbolic link lookup (works from standard user).

6. **Removed PrepareEicarOnDevice**: Writing files to `\Device\HarddiskVolumeN\RP_Temp\` requires admin — not viable for a standard-user exploit. The lock path now uses the junction-resolved temp dir path instead.

7. **Removed privilege escalation block**: The exploit runs as a standard user by design. Enabling SeDiskSecurityPrivilege etc. is pointless for a non-admin token and produces misleading console output.

## Credits

Original exploit by [Nightmare-Eclipse](https://github.com/MSNightmare/RoguePlanet).
Server modifications for authorized cyber exercise use only.