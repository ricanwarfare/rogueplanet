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

## Credits

Original exploit by [Nightmare-Eclipse](https://github.com/MSNightmare/RoguePlanet).
Server modifications for authorized cyber exercise use only.