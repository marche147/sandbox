
#include "stdafx.h"
#include <Windows.h>
#include <cstring>
#include <iostream>
#include <string>
#include <codecvt>
#include <Sddl.h>
#include "ConfigFile.h"
#include <strsafe.h>

//////////////////////////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////////////////////////

#ifdef _MSC_VER
#define INLINE __forceinline
#else
#define INLINE __attribute__((always_inline))
#endif

void usage(char* arg0) {
	printf("Usage : %s sandbox_profile target_program\n", arg0);
}

void fatal(const char* str) {
	printf("[FAILED] %s %d\n", str, GetLastError());
	_exit(-1);
}

INLINE PVOID halloc(SIZE_T Size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

INLINE BOOL hfree(PVOID Ptr) {
	return HeapFree(GetProcessHeap(), 0, Ptr);
}

HANDLE GetCurrentToken(void) {
	BOOL bResult;
	HANDLE hToken = NULL;

	bResult = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	if (bResult) {
		return hToken;
	}
	return NULL;
}

PVOID GetTokenInformationSimple(HANDLE hToken, TOKEN_INFORMATION_CLASS TokenInformationClass, LPDWORD pRetLength = NULL) {
	PVOID lpResult = NULL;
	BOOL bResult = FALSE;
	DWORD dwRetLength = 0;

	if (!GetTokenInformation(hToken, TokenInformationClass, NULL, 0, &dwRetLength)) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			lpResult = halloc(dwRetLength);
			if (!GetTokenInformation(hToken, TokenInformationClass, lpResult, dwRetLength, &dwRetLength)) {
				goto finished;
			}
		}
	}

	bResult = TRUE;
	if (pRetLength) {
		*pRetLength = dwRetLength;
	}

finished:
	if (!bResult && lpResult) {
		hfree(lpResult);
		lpResult = NULL;
	}
	return lpResult;
}

PTOKEN_GROUPS GetTokenSids(HANDLE hToken, LPDWORD pRetLength = NULL) {
	return reinterpret_cast<PTOKEN_GROUPS>(GetTokenInformationSimple(hToken, TokenGroups, pRetLength));
}

PTOKEN_PRIVILEGES GetTokenPrivileges(HANDLE hToken, LPDWORD pRetLength = NULL) {
	return reinterpret_cast<PTOKEN_PRIVILEGES>(GetTokenInformationSimple(hToken, TokenPrivileges, pRetLength));
}

BOOL HasPrivilege(LPCTSTR PrivilegeName) {
	HANDLE hToken = NULL;
	BOOL bResult = FALSE, bFound = FALSE;
	PTOKEN_PRIVILEGES tr = NULL;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		goto finished;
	}
	tr = GetTokenPrivileges(hToken);
	if (!tr) {
		goto finished;
	}
	if (!LookupPrivilegeValue(NULL, PrivilegeName, &luid)) {
		goto finished;
	}
	for (auto i = 0; i < tr->PrivilegeCount; i++) {
		if (luid.LowPart == tr->Privileges[i].Luid.LowPart && luid.HighPart == tr->Privileges[i].Luid.HighPart &&
			((tr->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) || (tr->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT))) {
			bFound = TRUE;
		}
	}
	if (!bFound) {
		goto finished;
	}
	bResult = TRUE;

finished:
	if (hToken) {
		CloseHandle(hToken);
	}
	if (tr) {
		hfree(tr);
	}
	return bResult;
}

BOOL EnablePrivileges(LPCTSTR PrivilegeName) {
	HANDLE hToken = NULL;
	BOOL bResult = FALSE, bFound = FALSE;
	PTOKEN_PRIVILEGES tr = NULL;
	DWORD dwSize;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		goto finished;
	}
	tr = GetTokenPrivileges(hToken, &dwSize);
	if (!tr) {
		goto finished;
	}
	if (!LookupPrivilegeValue(NULL, PrivilegeName, &luid)) {
		goto finished;
	}
	for (auto i = 0; i < tr->PrivilegeCount; i++) {
		if (luid.LowPart == tr->Privileges[i].Luid.LowPart && luid.HighPart == tr->Privileges[i].Luid.HighPart) {
			tr->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			bFound = TRUE;
		}
	}
	if (!bFound) {
		goto finished;
	}
	if (!AdjustTokenPrivileges(hToken, FALSE, tr, dwSize, NULL, NULL)) {
		goto finished;
	}
	bResult = TRUE;

finished:
	if (hToken) {
		CloseHandle(hToken);
	}
	if (tr) {
		hfree(tr);
	}
	return bResult;
}

//////////////////////////////////////////////////////////////////////////////////////////
// Main code
//////////////////////////////////////////////////////////////////////////////////////////

LPPROC_THREAD_ATTRIBUTE_LIST CraftProcThreadAttrib(ConfigFile& config) {
	DWORD dwAttribCount = 2;
	SIZE_T dwSize = 0;
	LPPROC_THREAD_ATTRIBUTE_LIST lpResult = NULL;
	BOOL bResult = FALSE;
	static ULONG64 dwMitigation = 0;	// damn it....
	static DWORD dwChild = 0;

	if (InitializeProcThreadAttributeList(NULL, dwAttribCount, 0, &dwSize) ||
		GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		lpResult = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(halloc(dwSize));
		if (!lpResult) {
			goto finished;
		}
		if (!InitializeProcThreadAttributeList(lpResult, dwAttribCount, 0, &dwSize)) {
			goto finished;
		}
	}
	else {
		goto finished;
	}

	if (config.getBool("no_child")) {
		dwChild = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
	}
	if (!UpdateProcThreadAttribute(lpResult, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &dwChild, sizeof(dwChild), NULL, NULL)) {
		goto finished;
	}

#define SET_ON_TRUE(key, option)  \
	if(config.getBool(#key)) { \
		dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_##option##_ALWAYS_ON; \
	} else { \
		dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_##option##_ALWAYS_OFF; \
	}

	SET_ON_TRUE(no_win32k, WIN32K_SYSTEM_CALL_DISABLE);
	SET_ON_TRUE(force_reloc, FORCE_RELOCATE_IMAGES);
	SET_ON_TRUE(critical_heap, HEAP_TERMINATE);
	SET_ON_TRUE(bottom_up_aslr, BOTTOM_UP_ASLR);
	SET_ON_TRUE(high_entropy_aslr, HIGH_ENTROPY_ASLR);
	SET_ON_TRUE(critical_handle, STRICT_HANDLE_CHECKS);
	SET_ON_TRUE(no_ep, EXTENSION_POINT_DISABLE);
	SET_ON_TRUE(no_dyncode, PROHIBIT_DYNAMIC_CODE);
	SET_ON_TRUE(no_fontload, FONT_DISABLE);
	SET_ON_TRUE(no_remote_img, IMAGE_LOAD_NO_REMOTE);
	SET_ON_TRUE(no_low_img, IMAGE_LOAD_NO_LOW_LABEL);
	SET_ON_TRUE(sysimg_prefer, IMAGE_LOAD_PREFER_SYSTEM32);
	if (config.getBool("dep")) {
		dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
		dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE;
	}
	if (config.getBool("sehop")) {
		dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
	}
#undef SET_ON_TRUE

	if (!UpdateProcThreadAttribute(lpResult, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwMitigation, sizeof(dwMitigation), NULL, NULL)) {
		goto finished;
	}

	bResult = TRUE;

finished:
	if (!bResult && lpResult) {
		hfree(lpResult);
		lpResult = NULL;
	}
	return lpResult;
}

HANDLE CraftJobObject(ConfigFile& config) {
	HANDLE hJob = NULL;
	BOOL bResult = FALSE;

	hJob = CreateJobObject(NULL, NULL);
	if (!hJob) {
		goto finished;
	}

#define SET_ON_TRUE(key) if(config.getBool(#key)) 
	SET_ON_TRUE(restrict_ui) {
		JOBOBJECT_BASIC_UI_RESTRICTIONS jbur;
		ZeroMemory(&jbur, sizeof(jbur));
		jbur.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
		if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbur, sizeof(jbur))) {
			goto finished;
		}
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
	ZeroMemory(&jeli, sizeof(jeli));
	jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
	jeli.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = config.getInt64("timeout", 5000000000i64);
	jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
	jeli.ProcessMemoryLimit = config.getInt("memory", 41943040);
	jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	jeli.BasicLimitInformation.ActiveProcessLimit = config.getInt("active_process", 1);
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
		goto finished;
	}
#undef SET_ON_TRUE

	bResult = TRUE;

finished:
	if (!bResult && hJob) {
		CloseHandle(hJob);
		hJob = NULL;
	}
	return hJob;
}



HANDLE CraftToken(ConfigFile& config) {
	HANDLE hToken = NULL;
	BOOL bResult = FALSE;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegrityLevelSid = NULL;
	TOKEN_MANDATORY_LABEL tml;
	DWORD dwIntLevel;

	std::string user = config.getString("user");
	std::string password = config.getString("password");
	std::string integrity_level = config.getString("integrity_level", "mid");
	bool restrict_token = config.getBool("restricted_token", true);
	bool remove_all_priv = config.getBool("remove_all_priv", true);
	Json::Value deny_sids = config.get("deny_sids");
	Json::Value restrict_sids = config.get("restrict_sids");
	Json::Value remove_privs = config.get("remove_privs");

	// use current token
	if (user == "") {
		HANDLE hMyToken = GetCurrentToken();
		hToken = hMyToken;
		bResult = TRUE;

		if (!bResult) {
			goto finished;
		}
	}
	else {
		if (HasPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
			// Great! We can assign primary tokens as we want! Use LogonUser to obtain the primary token!
			std::wstring userw(user.begin(), user.end());
			std::wstring passwordw(password.begin(), password.end());

			if (!LogonUser(userw.c_str(),
				TEXT("."),
				passwordw.c_str(),
				LOGON32_LOGON_INTERACTIVE,
				LOGON32_PROVIDER_DEFAULT,
				&hToken)) {
				goto finished;
			}
		}
		else {
			// Since most of the time we won't have AssignPrimaryToken privilege, we should use CreateProcessWithLogonW instead.
			goto finished;
		}
	}

	if (restrict_token) {
		PTOKEN_PRIVILEGES pRemovePriv = NULL;
		HANDLE hRestrictedToken = NULL;
		DWORD dwPrivCount = 0;
		PLUID_AND_ATTRIBUTES pPriv = NULL;
		DWORD dwDenySidCount = 0;
		PSID_AND_ATTRIBUTES pSids = NULL;
		DWORD dwRestrictSidCount = 0;
		PSID_AND_ATTRIBUTES pRestrictSid = NULL;
		HANDLE hNewToken = NULL;
		BOOL bSuccess = FALSE;

		if (remove_all_priv) {
			pRemovePriv = GetTokenPrivileges(hToken);
			if (!pRemovePriv) {
				goto blockend;
			}
			dwPrivCount = pRemovePriv->PrivilegeCount;
			pPriv = pRemovePriv->Privileges;
		}
		else if (remove_privs.size() > 0) {
			dwPrivCount = remove_privs.size();
			pPriv = reinterpret_cast<PLUID_AND_ATTRIBUTES>(halloc(sizeof(LUID_AND_ATTRIBUTES)* dwPrivCount));
			if (!pPriv) {
				goto blockend;
			}
			for (int index = 0; index < remove_privs.size(); index++) {
				std::string string_priv = remove_privs[index].asString();
				if (!LookupPrivilegeValueA(NULL, string_priv.c_str(), &pPriv[index].Luid)) {
					goto blockend;
				}
			}
		}

		if (deny_sids.size() > 0) {
			dwDenySidCount = deny_sids.size();
			pSids = reinterpret_cast<PSID_AND_ATTRIBUTES>(halloc(sizeof(SID_AND_ATTRIBUTES) * dwDenySidCount));
			if (!pSids) {
				goto blockend;
			}
			for (int index = 0; index < deny_sids.size(); index++) {
				std::string string_sid = deny_sids[index].asString();
				if (!ConvertStringSidToSidA(string_sid.c_str(), &pSids[index].Sid)) {
					goto blockend;
				}
			}
		}

		if (restrict_sids.size() > 0) {
			dwRestrictSidCount = restrict_sids.size();
			pRestrictSid = reinterpret_cast<PSID_AND_ATTRIBUTES>(halloc(sizeof(SID_AND_ATTRIBUTES) * dwRestrictSidCount));
			if (!pRestrictSid) {
				goto blockend;
			}
			for (int index = 0; index < restrict_sids.size(); index++) {
				std::string string_sid = restrict_sids[index].asString();
				if (!ConvertStringSidToSidA(string_sid.c_str(), &pRestrictSid[index].Sid)) {
					goto blockend;
				}
			}
		}

		bSuccess = CreateRestrictedToken(hToken, 0, dwDenySidCount, pSids, dwPrivCount, pPriv, dwRestrictSidCount, pRestrictSid, &hNewToken);
		if (bSuccess) {
			CloseHandle(hToken);
			hToken = hNewToken;
		}

	blockend:
		if (pRemovePriv) {
			hfree(pRemovePriv);
		}
		if (pSids) {
			hfree(pSids);
		}
		if (pRestrictSid) {
			hfree(pRestrictSid);
		}

		if (!bSuccess) {
			goto finished;
		}
	}

	// integrity level
	if (integrity_level == "untrust") {
		dwIntLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
	}
	else if (integrity_level == "low") {
		dwIntLevel = SECURITY_MANDATORY_LOW_RID;
	}
	else if (integrity_level == "mid") {
		dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
	}
	else if (integrity_level == "high") {
		dwIntLevel = SECURITY_MANDATORY_HIGH_RID;
	}
	else if (integrity_level == "system") {
		dwIntLevel = SECURITY_MANDATORY_SYSTEM_RID;
	}
	else {
		dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
	}
	if (!AllocateAndInitializeSid(&sia, 1, dwIntLevel, 0, 0, 0, 0, 0, 0, 0, &pIntegrityLevelSid)) {
		goto finished;
	}
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegrityLevelSid;
	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pIntegrityLevelSid))) {
		goto finished;
	}

	bResult = TRUE;

finished:
	if (!bResult && hToken) {
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (pIntegrityLevelSid) {
		FreeSid(pIntegrityLevelSid);
	}
	return hToken;
}



int main(int argc, char* argv[]) {
	if (argc < 3) {
		usage(argv[0]);
		_exit(1);
	}

	std::string appline(argv[2], argv[2] + strlen(argv[2]));

	ConfigFile cfg(argv[1]);
	LPPROC_THREAD_ATTRIBUTE_LIST pptal = NULL;
	HANDLE hJob = NULL, hToken = NULL;
	STARTUPINFOEX si;
	BOOL bResult;
	PROCESS_INFORMATION pi;

	if (!EnablePrivileges(SE_ASSIGNPRIMARYTOKEN_NAME)) {
		printf("Enable privilege failed %d\n", GetLastError());
	}

	hJob = CraftJobObject(cfg);
	if (!hJob) {
		fatal("CraftJobObject");
	}
	hToken = CraftToken(cfg);
	if (!hToken) {
		printf("CraftToken failed with %d, falling back to logon mode.\n", GetLastError());
	}
	pptal = CraftProcThreadAttrib(cfg);
	if (!pptal) {
		fatal("CraftProcThreadAttrib");
	}

	ZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(si);
	bool redir_io = cfg.getBool("redir_io");
	//HANDLE hReadPipe = NULL, hWritePipe = NULL;
	if (redir_io) {
		si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
		si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	}
	si.lpAttributeList = pptal;

	std::wstring applinew(appline.begin(), appline.end());
	if (hToken == NULL) {
		std::string user = cfg.getString("user");
		std::string password = cfg.getString("password");
		if (user == "") {
			printf("[FAILED] No username specified\n");
		}

		std::wstring userw(user.begin(), user.end());
		std::wstring passwordw(password.begin(), password.end());

		bResult = CreateProcessWithLogonW(userw.c_str(), TEXT("."), passwordw.c_str(), 0, applinew.c_str(), NULL, CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);
		if (!bResult) {
			fatal("CreateProcessWithLogonW");
		}
	}
	else {
		bResult = CreateProcessAsUser(hToken, applinew.c_str(), NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);
		if (!bResult) {
			fatal("CreateProcessAsUser");
		}
	}

	if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
		TerminateProcess(pi.hProcess, -1);
		fatal("AssignProcessToJobObject");
	}
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	int waitTime = cfg.getInt("wait_time", -1);
	if (WaitForSingleObject(pi.hProcess, waitTime) == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, -1);
		printf("[WARN] Process timed out\n");
	}

	DWORD dwExitCode;
	if (GetExitCodeProcess(pi.hProcess, &dwExitCode)) {
		printf("[DONE] Process exited with %u\n", dwExitCode);
	}
	else {
		printf("[ERR] Cannot get process exit code.\n");
	}

	hfree(pptal);
	CloseHandle(hJob);
	CloseHandle(pi.hProcess);
	CloseHandle(hToken);
	return 0;
}

