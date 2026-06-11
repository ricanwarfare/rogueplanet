# CHANGES — RoguePlanet Server Variant

Detailed changes from the original `RoguePlanet.cpp` to the Server-adapted `RoguePlanetServer.cpp`.

## New Functions

### `MountVHD()`
Replaces `MountISO()`. Creates a dynamic VHDX file using `CreateVirtualDisk`, then attempts to attach it read-only with `ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER`. If this succeeds (e.g., on Server with Hyper-V role), it provides the same `\Device\` path semantics as the ISO mount. Returns `true`/`false`.

### `GetSystemDevicePath()`
Fallback when no virtual disk can be mounted. Enumerates `\Device\` directory using `NtOpenDirectoryObject` + `NtQueryDirectoryObject` (standard users have `DIRECTORY_QUERY` access). Finds a `HarddiskVolume*` entry that:
1. The process can open (`FILE_READ_ATTRIBUTES | FILE_READ_DATA`)
2. Contains a `Windows` directory (confirms it's a real system volume, not a recovery partition)

Sets `g_devicepath` to e.g., `\Device\HarddiskVolume2`.

### `WriteEicarDirect(wchar_t* workdir)`
Writes the standard EICAR test string directly to `workdir\wermgr.exe` without reading from a mounted ISO. Then sets a restrictive DACL:
- **DENY** `GENERIC_WRITE | DELETE | FILE_WRITE_ATTRIBUTES` to Everyone (S-1-1-0)
- **ALLOW** `GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE` to Everyone

This makes the file "undeletable" to Defender, replicating the ISO's read-only filesystem behavior and forcing the same remediation fallback path.

### `WriteEicarServer(wchar_t* workdir, wchar_t* isomnt)`
Wrapper that calls original ISO-based `WriteEicar` logic if `isomnt` is provided, or `WriteEicarDirect` if NULL.

### `PrepareEicarOnDevice(wchar_t* devicepath, wchar_t* eicar_device_path_out)`
For the system device path fallback: creates `\Device\HarddiskVolumeN\RP_Temp\wermgr.exe` with EICAR content and read-only DACL. This file serves as the lock target in the race condition (replaces the ISO-mounted `wermgr.exe`).

## Modified Flow in main()

1. **Disk initialization:**
   ```
   ORIGINAL:  if (!MountISO(&hvirtdisk)) return 1;
   SERVER:    if (!MountVHD() && !GetSystemDevicePath()) { printf("No device path available\n"); return 1; }
   ```

2. **Device path:**
   ```
   ORIGINAL:  GetVirtualDiskPhysicalPath(hvirtdisk, &pathsz, _mntpath);
              mntpath = "\Device\" + PathFindFileName(_mntpath);
   SERVER:    wcscpy(mntpath, g_devicepath);  // Already set by MountVHD or GetSystemDevicePath
   ```

3. **EICAR write:**
   ```
   ORIGINAL:  HANDLE heicar = WriteEicar(maindirname, mntpath);
   SERVER:    HANDLE heicar = WriteEicarServer(maindirname, g_using_vhd ? mntpath : NULL);
   ```

4. **Lock path:**
   ```
   ORIGINAL:  lockpath = "\Device\CdRom0\wermgr.exe"  (from ISO)
   SERVER:    if (g_using_vhd) lockpath = "\Device\<VHD>\wermgr.exe"
              else lockpath = "\Device\HarddiskVolumeN\RP_Temp\wermgr.exe"
   ```

5. **Cleanup:**
   ```
   ORIGINAL:  DetachVirtualDisk(hvirtdisk, ...); CloseHandle(hvirtdisk);
   SERVER:    if (g_using_vhd) { DetachVirtualDisk(g_hvhd, ...); CloseHandle(g_hvhd); }
              else { Delete RP_Temp directory from system volume; }
   ```

## Global State

- `g_devicepath` — The `\Device\` path used for junctions and locks
- `g_using_vhd` — `true` if VHD mount succeeded, `false` if using system device path
- `g_hvhd` — Handle to VHD (valid only when `g_using_vhd == true`)

## Unchanged Components

All other exploit primitives remain identical:
- `CreateJunction()` — NTFS mount point reparse points
- `PoseidonThread()` / `PoseidonGeneratorThread()` — Race condition timing threads
- `WDStartScan()` — Defender MpClient.dll API calls
- `MpCleanCallbackFunction()` — Defender cleanup race
- `ShadowCopyFinderThread()` — VSS snapshot enumeration
- `LockFile()` — File locking for timing control
- `DeviceIoControl(FSCTL_REQUEST_OPLOCK)` — Oplock-based timing
- `ReadDirectoryChangesW()` — Filesystem change monitoring
- Task Scheduler COM — `QueueReporting` task execution
- Named pipe — `\\.\pipe\RoguePlanet` SYSTEM shell handoff

## Limitations

1. **DACL-based read-only is weaker than ISO read-only** — An admin could override the DACL, but Defender's cleanup runs as SYSTEM and respects DACLs, so the behavior matches for the race window.

2. **`RP_Temp` directory on system volume** — Leaves a visible artifact. Cleanup is attempted but may fail if Defender holds handles.

3. **Race reliability** — Same variable success rate as original. The Server variant adds slightly more timing variability due to the writable filesystem (vs. inherently read-only ISO).

4. **Windows Defender must be active** — Same requirement as original. Server Core without Defender GUI may still have the engine running.

5. **Standard user on Server with no virtual disk access** — The system device path approach works but requires that `\Device\HarddiskVolume*` paths are accessible. Some hardened Server configurations restrict this.