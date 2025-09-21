#pragma once
#include <Windows.h>
#include <TlHelp32.h>

constexpr auto IOCTL_MEM_RW = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr auto IOCTL_PROC_BASE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr auto IOCTL_POOL_SCAN = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr int AUTH_KEY = 0xC4B9E2A1;

struct MEM_RW {
	int32_t auth, procId;
	uint64_t vAddr, buffer, size;
	bool isWrite;
};

struct PROC_BASE {
	int32_t auth, procId;
	uint64_t* result;
};

struct POOL_SCAN {
	int32_t auth;
	uint64_t* result;
};

namespace driver {
	inline HANDLE h = INVALID_HANDLE_VALUE;
	inline int32_t pid = 0;

	inline bool connect() {
		if (h != INVALID_HANDLE_VALUE) return true;
		h = CreateFileA(R"(\\.\k9mPq3vL7x)", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		return h != INVALID_HANDLE_VALUE;
	}

	inline bool send(DWORD code, void* in, DWORD size) {
		DWORD out;
		return DeviceIoControl(h, code, in, size, nullptr, 0, &out, nullptr) != FALSE;
	}

	inline void poke(void* target, void* src, DWORD size) {
		MEM_RW args{ AUTH_KEY, pid, (uint64_t)target, (uint64_t)src, size, true };
		send(IOCTL_MEM_RW, &args, sizeof(args));
	}

	inline void peek(void* target, void* dst, DWORD size) {
		MEM_RW args{ AUTH_KEY, pid, (uint64_t)target, (uint64_t)dst, size, false };
		send(IOCTL_MEM_RW, &args, sizeof(args));
	}

	inline uintptr_t GetProcessBase() {
		uint64_t out = 0;
		PROC_BASE args{ AUTH_KEY, pid, &out };
		send(IOCTL_PROC_BASE, &args, sizeof(args));
		return out;
	}

	inline uintptr_t guarded() {
		uint64_t out = 0;
		POOL_SCAN args{ AUTH_KEY, &out };
		send(IOCTL_POOL_SCAN, &args, sizeof(args));
		return out;
	}

	inline int32_t FindProcess(const char* name) {
		PROCESSENTRY32W pe{ sizeof(pe) };
		auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) return 0;
		if (Process32FirstW(snap, &pe)) {
			do {
				if (!_wcsicmp(pe.szExeFile, std::wstring(name, name + strlen(name)).c_str())) {
					pid = pe.th32ProcessID;
					CloseHandle(snap);
					return pid;
				}
			} while (Process32NextW(snap, &pe));
		}
		CloseHandle(snap);
		return 0;
	}
}

template<typename T>
inline T read(uint64_t addr) {
	T out{};
	driver::peek((void*)addr, &out, sizeof(T));
	return out;
}

template<typename T>
inline void write(uint64_t addr, const T& val) {
	driver::poke((void*)addr, (void*)&val, sizeof(T));
}
