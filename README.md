Driver Loader Project
Overview
This project loads a kernel driver (driver.sys) using KDMapper with iqvw64e.sys and interacts with it via driver.hpp for memory read/write and process base address retrieval.
Requirements

Windows 10/11
Visual Studio (C++)
Windows Driver Kit (WDK)
iqvw64e.sys and KDMapper
Admin privileges

Files

main.cpp: Loads and connects to the driver.
driver.hpp: Interface for memory operations.
driver.cpp: Kernel driver source (compile to driver.sys).
iqvw64e.sys: Vulnerable driver for KDMapper.

Setup

Save main.cpp, driver.hpp, driver.cpp in one folder.
Place driver.sys (from driver.cpp) and iqvw64e.sys in the same folder.
Compile driver.cpp with WDK to get driver.sys.
Compile main.cpp with Visual Studio, linking advapi32.lib.

Usage

Run main.exe as Administrator.

It loads iqvw64e.sys, maps driver.sys, and connects.

Check output:

Success: [SUCCESS] Driver successfully mapped
Error: Check file paths or privileges.


Use driver.hpp functions:

driver::read<T>(addr): Read memory.
driver::write<T>(addr, value): Write memory.
driver::GetProcessBase(): Get process base.
driver::FindProcess("name.exe"): Set process ID.



Example
#include "driver.hpp"
int main() {
    if (driver::connect()) {
        driver::FindProcess("notepad.exe");
        uintptr_t base = driver::GetProcessBase();
        uint32_t value = driver::read<uint32_t>(base + 0x1000);
    }
    return 0;
}

Notes

Test in a VM to avoid crashes.
Uses stealthy names (k9mPq3vL7x) and custom IOCTLs.
Ensure iqvw64e.sys and KDMapper are set up.
Run as Admin.

Warning
Use carefully in a test environment.

yes its an ai description fuck u
