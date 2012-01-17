#include <windows.h>
#include <atlstr.h>
#include "common.h"
#include "Utility.h"
#include "UmdhProcessor.h"

UmdhProcessor::UmdhProcessor(PCSTR filename)
: output_(INVALID_HANDLE_VALUE)
{
	LPSTR buffer[MAX_PATH];
	if (!GetCurrentDirectory(_countof(buffer),(LPSTR)buffer))
	{
		throw -1;
	}
	dprintf("current directory: %s\n", buffer);

	output_ = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (output_ == INVALID_HANDLE_VALUE)
	{
		DWORD lastError = GetLastError();
		switch (lastError)
		{
		case ERROR_FILE_EXISTS:
			dprintf("%s already exists\n", filename);
			break;
		case ERROR_PATH_NOT_FOUND:
			dprintf("%s path not found\n", filename);
			break;
		default:
			dprintf("cannot create %s (%d)\n", filename, lastError);
			break;
		}
		throw -1;
	}
	CString str = "// Loaded modules:\n"
		"//     Base Size Module\n";

	std::vector<ModuleInfo> modules = GetLoadedModules();
	for (std::vector<ModuleInfo>::iterator itr = modules.begin(); itr != modules.end(); itr++)
	{
		CString line;
		line.Format("//    %16I64X %8I64X %s\n", itr->DllBase, itr->SizeOfImage, itr->FullDllName);
		str += line;
	}
	str += "//\n";
	DWORD written;
	if (!WriteFile(output_, (LPCSTR)str, str.GetLength(), &written, NULL) || written != (DWORD)str.GetLength())
	{
		dprintf("%s: WriteFile failed %d (written %d)\n", __FUNCTION__, GetLastError(), written);
		CloseHandle(output_);
		output_ = INVALID_HANDLE_VALUE;
		throw -1;
	}
}

UmdhProcessor::~UmdhProcessor()
{
	if (output_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(output_);
	}
}

void UmdhProcessor::StartHeap(ULONG64 heapAddress)
{
	if (output_ == INVALID_HANDLE_VALUE)
	{
		return;
	}
	CString str;
	str.Format("\n"
		"*- - - - - - - - - - Start of data for heap @ %I64X - - - - - - - - - -\n"
		"\n"
		"REQUESTED bytes + OVERHEAD at ADDRESS by BackTraceID\n"
		"     STACK if not already dumped.\n"
		"\n"
		"*- - - - - - - - - - Heap %I64X Hogs - - - - - - - - - -\n"
		"\n",
		heapAddress, heapAddress);
	
	DWORD written;
	if (!WriteFile(output_, (LPCSTR)str, str.GetLength(), &written, NULL) || written != (DWORD)str.GetLength())
	{
		dprintf("%s: WriteFile failed %d (written %d)\n", __FUNCTION__, GetLastError(), written);
		CloseHandle(output_);
		output_ = INVALID_HANDLE_VALUE;
	}
}

void UmdhProcessor::FinishHeap(ULONG64 heapAddress)
{
	if (output_ == INVALID_HANDLE_VALUE)
	{
		return;
	}
	CString str;
	str.Format("\n"
		"*- - - - - - - - - - End of data for heap @ %I64X - - - - - - - - - -\n"
		"\n", heapAddress);

	DWORD written;
	if (!WriteFile(output_, (LPCSTR)str, str.GetLength(), &written, NULL) || written != (DWORD)str.GetLength())
	{
		dprintf("%s: WriteFile failed %d (written %d)\n", __FUNCTION__, GetLastError(), written);
		CloseHandle(output_);
		output_ = INVALID_HANDLE_VALUE;
	}
	processed_.clear();
}

void UmdhProcessor::Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress)
{
	UNREFERENCED_PARAMETER(address);

	ULONG64 backtrace = ustAddress != 0 ? GetStackTraceArrayPtr(ustAddress) : 0;
	CString str;
	str.Format("%I64X bytes + %I64X at %I64X by BackTrace%I64X\n",
		userSize, size - userSize, userAddress, backtrace);
	if (ustAddress != 0 && processed_.find(backtrace) == processed_.end())
	{
		str = "\n" + str;
		std::vector<ULONG64> trace = ::GetStackTrace(ustAddress);
		for (std::vector<ULONG64>::iterator itr = trace.begin(); itr != trace.end(); itr++)
		{
			CString line;
			line.Format("\t%I64X\n", *itr);
			str += line;
		}
		str += "\n";
		processed_.insert(backtrace);
	}

	DWORD written;
	if (!WriteFile(output_, (LPCSTR)str, str.GetLength(), &written, NULL) || written != (DWORD)str.GetLength())
	{
		dprintf("%s: WriteFile failed %d (written %d)\n", __FUNCTION__, GetLastError(), written);
		CloseHandle(output_);
		output_ = INVALID_HANDLE_VALUE;
	}
}
