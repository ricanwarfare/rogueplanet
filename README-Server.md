# RoguePlanet — Server Variant

Windows Defender LPE exploit modified to work on **Windows Server** where standard users cannot mount ISO images via `AttachVirtualDisk`.

**For authorized cyber exercises only.**

## Problem

The original RoguePlanet exploit requires mounting an ISO image using `AttachVirtualDisk` (VHD/ISO Virtual Disk API). On Windows Server (all versions), this operation requires Administrator privileges — a standard user gets `ERROR_ACCESS_DENIED`.

The ISO mount serves three purposes in the original exploit chain:
1. Provides a `\Device\` path (e.g., `\Device\CdRom0`) via `GetVirtualDiskPhysicalPath`
2. Contains a read-only `wermgr.exe` (EICAR test file) that Defender detects
3. The read-only filesystem forces Defender into a specific remediation fallback path

## Solution: Two-Pronged Approach

### Approach 1: VHD Mount
Try `CreateVirtualDisk` (dynamic VHDX) + `AttachVirtualDisk`. This may succeed on some Server configurations where:
- Hyper-V role is installed (VHD operations are enabled)
- The user has `SeVirtualDiskPrivilege` (rare but possible in misconfigured environments)
- GPO has loosened virtual disk restrictions

### Approach 2: System Device Path Fallback (Primary Server Method)
If VHD mount fails, enumerate `\Device\HarddiskVolume*` using `NtOpenDirectoryObject`/`NtQueryDirectoryObject` (standard users CAN do this) and find an accessible NTFS system volume.

This gives us the `\Device\` path we need for junctions, but we lose the read-only filesystem. We compensate by:

1. **Writing EICAR directly** to the working directory using the standard EICAR test string instead of reading from the ISO
2. **Setting a restrictive DACL** on the EICAR file that denies `DELETE` and `GENERIC_WRITE` to Everyone — this makes the file "undeletable" by Defender, forcing the same remediation fallback as the read-only ISO
3. **Placing a lockable EICAR file** on the system volume at `\Device\HarddiskVolumeN\RP_Temp\wermgr.exe` for the lock-based timing primitive

## Key Changes from Original

| Component | Original | Server Variant |
|---|---|---|
| Disk mount | `MountISO()` → `AttachVirtualDisk` on ISO | `MountVHD()` first, then `GetSystemDevicePath()` fallback |
| Device path | From `GetVirtualDiskPhysicalPath` on ISO | `\Device\HarddiskVolumeN` from system enumeration |
| EICAR source | Read `wermgr.exe` from mounted ISO | Write EICAR string directly + restrictive DACL |
| Read-only semantics | ISO filesystem is inherently read-only | File DACL denies DELETE/WRITE to simulate |
| Lock target | `\Device\CdRom0\wermgr.exe` | `\Device\HarddiskVolumeN\RP_Temp\wermgr.exe` |
| Cleanup | `DetachVirtualDisk` | Delete `RP_Temp` directory from system volume |

## Files

- `RoguePlanetServer.cpp` — Server-adapted source with VHD + system device fallback
- `RoguePlanet.cpp` — Original source (unchanged, for reference)
- `CHANGES.md` — Detailed diff from original

## Building

Requires Visual Studio 2019+ or MinGW with Windows SDK:

```bash
# MSVC
cl /EHsc /std:c++17 /link kernel32.lib bcrypt.lib taskschd.lib comsupp.lib virtdisk.lib ntdll.lib Rpcrt4.lib shlwapi.lib RoguePlanetServer.cpp

# MinGW
g++ -o RoguePlanetServer.exe RoguePlanetServer.cpp -lkernel32 -lbcrypt -ltaskschd -lcomsupp -lvirtdisk -lntdll -lRpcrt4 -lshlwapi -mwindows
```

## Detection Implications

The Server variant creates additional detection signals:

- `\Device\HarddiskVolume*\RP_Temp\wermgr.exe` — unusual path on system volume
- DACL manipulation on EICAR files (denying DELETE to Everyone)
- `NtOpenDirectoryObject("\Device")` + `NtQueryDirectoryObject` enumeration
- `%TEMP%\RP_*` working directory (same as original)
- All original signals remain: Defender scan, VSS access, junction creation, oplocks, QueueReporting task execution

## Testing

Tested against:
- [ ] Windows Server 2022 (standard user, no Hyper-V role)
- [ ] Windows Server 2025 (standard user, no Hyper-V role)
- [ ] Windows Server 2022 with Hyper-V role (VHD mount may work)
- [ ] Windows Server Core variants

## Original Credits

Original exploit by [Nightmare-Eclipse](https://github.com/Nightmare-Eclipse) / Project NightCrawler.
Server modifications for authorized cyber exercise use only.