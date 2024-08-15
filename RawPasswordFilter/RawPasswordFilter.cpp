#include "pch.h"
#include "RawPasswordFilter.h"
#include <winternl.h>
#include <ntstatus.h>


bool InitializeChangeNotify() {
	return true;
}

NTSTATUS PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) {
	
	return STATUS_SUCCESS;
}

bool PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, bool SetOperation) {
	return true;
}
