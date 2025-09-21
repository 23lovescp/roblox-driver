#include <iostream>
#include <Windows.h>
#include "driver.hpp"


// 
bool LoadDriver(const wchar_t* driverPath, const wchar_t* serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::cout << "[-] Failed to open SCM, error: " << GetLastError() << std::endl;
        return false;
    }

    [+] SC_HANDLE hService = CreateServiceW(hSCManager, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hService && GetLastError() != ERROR_SERVICE_EXISTS) {
        std::cout << "[-] Failed to create service, error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }
    if (!hService) {
        hService = OpenServiceW(hSCManager, serviceName, SERVICE_ALL_ACCESS);
        if (!hService) {
            std::cout << "[-] Failed to open existing service, error: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    [+] BOOL success = StartServiceW(hService, 0, nullptr);
    if (!success && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        std::cout << "[-] Failed to start service, error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool UnloadDriver(const wchar_t* serviceName) {
    [+] SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::cout << "[-] Failed to open SCM for unload, error: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_ALL_ACCESS);
    if (!hService) {
        std::cout << "[-] Failed to open service for unload, error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        std::cout << "[-] Failed to stop service, error: " << GetLastError() << std::endl;
    }

    if (!DeleteService(hService)) {
        std::cout << "[-] Failed to delete service, error: " << GetLastError() << std::endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

int main() {
    [-] const wchar_t* driverPath = L".\\driver.sys";
    [-] const wchar_t* serviceName = L"k9mPq3vL7xSvc";
    [+] const wchar_t* driverPath = L".\\iqvw64e.sys";
    [+] const wchar_t* serviceName = L"IQVW64E";

    if (driver::connect()) {
        std::cout << "[INFO] Driver already loaded" << std::endl;
    }
    else {
        HANDLE h = intel_driver::Load();
        if (!h || h == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::cout << "[-] Failed to load vulnerable driver, code: " << err << std::endl;
            std::cin.get();
            return 1;
        }

        std::cout << "[+] Vulnerable driver loaded successfully" << std::endl;

        if (intel_driver::ClearPiDDBCacheTable(h)) {
            std::cout << "[INFO] PiDDBCacheTable cleaned" << std::endl;
        }
        else {
            std::cout << "[-] Failed to clean PiDDBCacheTable (its okay)" << std::endl;
        }

        if (intel_driver::ClearMmUnloadedDrivers(h)) {
            std::cout << "[INFO] MmUnloadedDrivers cleaned" << std::endl;
        }
        else {
            std::cout << "[-] Failed to clean MmUnloadedDrivers (its okay)" << std::endl;
        }

        if (!kdmapper::MapDriver(h, DRIVERbytes)) {
            std::cout << "[-] Failed to map driver" << std::endl;
            intel_driver::Unload(h);
            std::cin.get();
            return 1;
        }

        intel_driver::Unload(h);

        if (!driver::connect()) {
            std::cout << "[-] Driver still not loaded (cooked)" << std::endl;
            std::cin.get();
            return 1;
        }

        std::cout << "[SUCCESS] Driver successfully mapped" << std::endl;
    }

    return 0;
}
