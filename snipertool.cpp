#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

struct Patron {
    std::vector<BYTE> buscar;
    std::vector<BYTE> reemplazar;
    std::string nombre;
};

DWORD BuscarProcesoEmulador() {
    const char* emuladores[] = {
        "HD-Player.exe", "MEmuHeadless.exe",
        "aow_exe.exe", "AndroidProcess.exe",
        "LdVBoxHeadless.exe", "Nox.exe"
    };

    PROCESSENTRY32 entrada;
    entrada.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &entrada)) {
        do {
            for (const auto& nombre : emuladores) {
                if (strstr(entrada.szExeFile, nombre)) {
                    CloseHandle(snapshot);
                    std::cout << "[+] Emulador encontrado: " << entrada.szExeFile << " (PID: " << entrada.th32ProcessID << ")\n";
                    return entrada.th32ProcessID;
                }
            }
        } while (Process32Next(snapshot, &entrada));
    }
    CloseHandle(snapshot);
    return 0;
}

bool Comparar(const BYTE* datos, const std::vector<BYTE>& patron) {
    for (size_t i = 0; i < patron.size(); ++i) {
        if (patron[i] != datos[i]) return false;
    }
    return true;
}

bool EscanearYParchear(HANDLE proceso, const Patron& p) {
    MEMORY_BASIC_INFORMATION info;
    BYTE buffer[4096];
    uintptr_t direccion = 0;
    SIZE_T bytesLeidos;
    bool parcheado = false;

    while (VirtualQueryEx(proceso, (LPCVOID)direccion, &info, sizeof(info))) {
        if (info.State == MEM_COMMIT && (info.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            for (uintptr_t offset = 0; offset < info.RegionSize; offset += sizeof(buffer)) {
                SIZE_T tam = (info.RegionSize - offset < sizeof(buffer)) ? (info.RegionSize - offset) : sizeof(buffer);
                uintptr_t direccionLectura = direccion + offset;
                if (ReadProcessMemory(proceso, (LPCVOID)direccionLectura, buffer, tam, &bytesLeidos)) {
                    for (SIZE_T i = 0; i <= bytesLeidos - p.buscar.size(); ++i) {
                        if (Comparar(buffer + i, p.buscar)) {
                            uintptr_t dirPatch = direccionLectura + i;
                            DWORD oldProtect;
                            VirtualProtectEx(proceso, (LPVOID)dirPatch, p.reemplazar.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
                            WriteProcessMemory(proceso, (LPVOID)dirPatch, p.reemplazar.data(), p.reemplazar.size(), nullptr);
                            VirtualProtectEx(proceso, (LPVOID)dirPatch, p.reemplazar.size(), oldProtect, &oldProtect);
                            std::cout << "[+] " << p.nombre << " parcheado en 0x" << std::hex << dirPatch << std::dec << "\n";
                            parcheado = true;
                        }
                    }
                }
            }
        }
        direccion += info.RegionSize;
    }
    return parcheado;
}

int main() {
    std::cout << "== SNIPER / AIM PATCH TOOL ==\n";

    DWORD pid = BuscarProcesoEmulador();
    if (!pid) {
        std::cerr << "[-] No se encontró emulador en ejecución.\n";
        std::cin.get();
        return 1;
    }

    HANDLE proceso = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proceso) {
        std::cerr << "[-] No se pudo abrir el proceso. Ejecuta como administrador.\n";
        std::cin.get();
        return 1;
    }

    std::vector<Patron> patrones = {
        {
            {0xDC, 0x52, 0x39, 0xBD, 0x27, 0xC1, 0x8B, 0x3C, 0xC0, 0xD0, 0xF8, 0xB9},
            {0x00, 0x00, 0x00, 0x3E, 0x0A, 0xD7, 0x23, 0x3D, 0xD2, 0xA5, 0xF9, 0xBC},
            "AimSniper1"
        },
        {
            {0x63, 0x71, 0xB0, 0xBD, 0x90, 0x98, 0x74, 0xBB, 0x00, 0x00, 0x80, 0xB3},
            {0xCD, 0xDC, 0x79, 0x44, 0x90, 0x98, 0x74, 0xBB, 0x00, 0x00, 0x80, 0xB3},
            "AimSniper2"
        },
        {
            {0x5D, 0xC1, 0xAB, 0x2C, 0x09, 0x04, 0xFF, 0x18, 0xEF, 0xE5, 0x11, 0x59},
            {0xCD, 0xDC, 0x79, 0x44, 0x58, 0x34, 0x09, 0xBB, 0xB0, 0x60, 0xBE, 0xBA},
            "AntiCheat2"
        },
        {
            {0x21, 0x60, 0x29, 0x1C, 0x80, 0xA2, 0xF4, 0x00, 0xC8, 0xD1, 0x85, 0xDE},
            {0xCD, 0xDC, 0x79, 0x44, 0x58, 0x34, 0x09, 0xBB, 0xB0, 0x60, 0xBE, 0xBA},
            "AntiCheatPatch"
        }
    };

    bool alguno = false;
    for (const auto& p : patrones) {
        if (EscanearYParchear(proceso, p)) alguno = true;
    }

    CloseHandle(proceso);

    if (alguno)
        std::cout << "[+] Parches aplicados con éxito.\n";
    else
        std::cerr << "[-] No se encontraron patrones.\n";

    std::cin.get();  // para que no se cierre la consola
    return 0;
}
