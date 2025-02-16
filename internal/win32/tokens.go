package win32

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
)

const (
	SE_BACKUP_NAME                         = "SeBackupPrivilege"
	SE_CHANGENOTIFY_NAME                   = "SeChangeNotifyPrivilege"
	SE_CREATEGLOBAL_NAME                   = "SeCreateGlobalPrivilege"
	SE_CREATEPAGEFILE_NAME                 = "SeCreatePagefilePrivilege"
	SE_CREATESYMBOLICLINK_NAME             = "SeCreateSymbolicLinkPrivilege"
	SE_DEBUG_NAME                          = "SeDebugPrivilege"
	SE_DELEGATESESSIONUSERIMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege"
	SE_IMPERSONATE_NAME                    = "SeImpersonatePrivilege"
	SE_INCREASEBASEPRIORITY_NAME           = "SeIncreaseBasePriorityPrivilege"
	SE_INCREASEQUOTA_NAME                  = "SeIncreaseQuotaPrivilege"
	SE_INCREASEWORKINGSET_NAME             = "SeIncreaseWorkingSetPrivilege"
	SE_LOADDRIVER_NAME                     = "SeLoadDriverPrivilege"
	SE_MANAGEVOLUME_NAME                   = "SeManageVolumePrivilege"
	SE_PROFILESINGLEPROCESS_NAME           = "SeProfileSingleProcessPrivilege"
	SE_REMOTESHUTDOWN_NAME                 = "SeRemoteShutdownPrivilege"
	SE_RESTORE_NAME                        = "SeRestorePrivilege"
	SE_SECURITY_NAME                       = "SeSecurityPrivilege"
	SE_SHUTDOWN_NAME                       = "SeShutdownPrivilege"
	SE_SYSTEMENVIRONMENT_NAME              = "SeSystemEnvironmentPrivilege"
	SE_SYSTEMPROFILE_NAME                  = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME                     = "SeSystemtimePrivilege"
	SE_TAKEOWNERSHIP_NAME                  = "SeTakeOwnershipPrivilege"
	SE_TIMEZONE_NAME                       = "SeTimeZonePrivilege"
	SE_UNDOCK_NAME                         = "SeUndockPrivilege"

	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000
	SECURITY_MANDATORY_LOW_RID               = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000
	SECURITY_MANDATORY_MEDIUM_PLUS_RID       = 0x00002100
	SECURITY_MANDATORY_HIGH_RID              = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000
)

var (
	AllPrivileges = []string{
		SE_BACKUP_NAME,
		SE_CHANGENOTIFY_NAME,
		SE_CREATEGLOBAL_NAME,
		SE_CREATEPAGEFILE_NAME,
		SE_CREATESYMBOLICLINK_NAME,
		SE_DEBUG_NAME,
		SE_DELEGATESESSIONUSERIMPERSONATE_NAME,
		SE_IMPERSONATE_NAME,
		SE_INCREASEBASEPRIORITY_NAME,
		SE_INCREASEQUOTA_NAME,
		SE_INCREASEWORKINGSET_NAME,
		SE_LOADDRIVER_NAME,
		SE_MANAGEVOLUME_NAME,
		SE_PROFILESINGLEPROCESS_NAME,
		SE_REMOTESHUTDOWN_NAME,
		SE_RESTORE_NAME,
		SE_SECURITY_NAME,
		SE_SHUTDOWN_NAME,
		SE_SYSTEMENVIRONMENT_NAME,
		SE_SYSTEMPROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_TAKEOWNERSHIP_NAME,
		SE_TIMEZONE_NAME,
		SE_UNDOCK_NAME,
	}
)

const (
	// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
	PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF
)

var (
	IntegrityMapping = map[uint32]string{
		SECURITY_MANDATORY_UNTRUSTED_RID:         "Untrusted",
		SECURITY_MANDATORY_LOW_RID:               "Low",
		SECURITY_MANDATORY_MEDIUM_RID:            "Medium",
		SECURITY_MANDATORY_MEDIUM_PLUS_RID:       "Medium+",
		SECURITY_MANDATORY_HIGH_RID:              "High",
		SECURITY_MANDATORY_SYSTEM_RID:            "System",
		SECURITY_MANDATORY_PROTECTED_PROCESS_RID: "Protected",
	}
)

// GetTokenIntegrityLevel enumerates the integrity level for the provided token and returns it as a string
func GetTokenIntegrityLevel(token windows.Token) (uint32, error) {
	var info byte
	var returnedLen uint32

	// Call to get structure size
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &info, 0, &returnedLen)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return 0xfffffff, fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	// Call again to get the actual structure
	TokenIntegrityInformation := bytes.NewBuffer(make([]byte, returnedLen))
	err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &TokenIntegrityInformation.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		return 0xfffffff, fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	bLabel := make([]byte, returnedLen)
	err = binary.Read(TokenIntegrityInformation, binary.LittleEndian, &bLabel)
	if err != nil {
		return 0xfffffff, fmt.Errorf("there was an error reading the token integrity level: %s", err)
	}

	// Integrity level is in the Attributes portion of the structure, a DWORD, the last four bytes
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_and_attributes
	integrityLevel := binary.LittleEndian.Uint32(bLabel[returnedLen-4:])
	return integrityLevel, nil
}
