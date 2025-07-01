import ctypes
import tkinter as tk
from tkinter import ttk
import psutil
import winsound
import threading
import time
import sys
from ctypes import wintypes

# Definiciones de Windows
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MemoryPatcher:
    def __init__(self):
        self.process = None
        self.pid = None
        self.emulator_name = ""
        self.original_data = {}
        self.emulators = [
            "HD-Player.exe", "MEmuHeadless.exe",
            "aow_exe.exe", "AndroidProcess.exe",
            "LdVBoxHeadless.exe", "Nox.exe"
        ]
        
        # Patrones actualizados
        self.patterns = [
            {
                "name": "AimSniper1",
                "search": b"\xDC\x52\x39\xBD\x27\xC1\x8B\x3C\xC0\xD0\xF8\xB9",
                "replace": b"\x00\x00\x00\x3E\x0A\xD7\x23\x3D\xD2\xA5\xF9\xBC",
                "active": False
            },
            {
                "name": "AimSniper2",
                "search": b"\x63\x71\xB0\xBD\x90\x98\x74\xBB\x00\x00\x80\xB3",
                "replace": b"\xCD\xDC\x79\x44\x90\x98\x74\xBB\x00\x00\x80\xB3",
                "active": False
            },
            {
                "name": "AntiCheat1",
                "search": b"\x5D\xC1\xAB\x2C\x09\x04\xFF\x18\xEF\xE5\x11\x59",
                "replace": b"\xCD\xDC\x79\x44\x58\x34\x09\xBB\xB0\x60\xBE\xBA",
                "active": False
            },
            {
                "name": "AntiCheat2",
                "search": b"\x21\x60\x29\x1C\x80\xA2\xF4\x00\xC8\xD1\x85\xDE",
                "replace": b"\xCD\xDC\x79\x44\x58\x34\x09\xBB\xB0\x60\xBE\xBA",
                "active": False
            },
            {
                "name": "MemoryPatch1",
                "search": b"\x8B\x45\x08\x85\xC0\x74\x0F",
                "replace": b"\xB8\x01\x00\x00\x00\x90\x90",
                "active": False
            },
            {
                "name": "MemoryPatch2",
                "search": b"\x75\x1D\x8B\x45\xF4",
                "replace": b"\x90\x90\x8B\x45\xF4",
                "active": False
            }
        ]

    def find_emulator(self):
        for proc in psutil.process_iter(['pid', 'name']):
            for emu in self.emulators:
                if emu.lower() in proc.info['name'].lower():
                    self.pid = proc.info['pid']
                    self.emulator_name = proc.info['name']
                    return True
        return False

    def open_process(self):
        self.process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        return self.process is not None

    def deep_scan(self, pattern):
        if not self.process:
            return False, 0

        # Configuración de estructuras
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        found = False
        address_found = 0
        buffer_size = 4096
        search_bytes = pattern["search"]
        len_search = len(search_bytes)

        while address < 0x7FFFFFFF0000:  # Espacio de usuario en 64 bits
            try:
                result = kernel32.VirtualQueryEx(self.process, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not result:
                    break
                
                # Solo regiones comprometidas y legibles
                if mbi.State == MEM_COMMIT and (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ)):
                    buffer = (ctypes.c_byte * buffer_size)()
                    bytes_read = wintypes.SIZE_T()
                    total_size = min(buffer_size, mbi.RegionSize)
                    
                    if kernel32.ReadProcessMemory(self.process, mbi.BaseAddress, buffer, total_size, ctypes.byref(bytes_read)):
                        data = bytes(buffer)
                        
                        # Búsqueda más eficiente
                        pos = data.find(search_bytes)
                        if pos != -1:
                            address_found = mbi.BaseAddress + pos
                            found = True
                            break
                
                address = mbi.BaseAddress + mbi.RegionSize
            except:
                address += 0x10000

        return found, address_found

    def patch_memory(self, pattern, activate=True):
        found, address = self.deep_scan(pattern)
        if not found:
            return False

        # Obtener datos originales si es necesario
        if address not in self.original_data:
            self.original_data[address] = pattern["search"]
        
        # Preparar datos para escribir
        if activate:
            data_to_write = pattern["replace"]
        else:
            data_to_write = self.original_data[address]
        
        # Cambiar protección de memoria
        old_protect = wintypes.DWORD()
        kernel32.VirtualProtectEx(self.process, address, len(data_to_write), 
                                 PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
        
        # Escribir en memoria
        written = wintypes.SIZE_T()
        kernel32.WriteProcessMemory(self.process, address, data_to_write, len(data_to_write), ctypes.byref(written))
        
        # Restaurar protección
        kernel32.VirtualProtectEx(self.process, address, len(data_to_write), 
                                 old_protect, ctypes.byref(old_protect))
        
        return written.value == len(data_to_write)

    def close_process(self):
        if self.process:
            kernel32.CloseHandle(self.process)
            self.process = None

class SniperToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Sniper/Aim Patch Tool")
        self.root.geometry("600x550")
        self.root.resizable(True, True)
        
        self.patcher = MemoryPatcher()
        self.searching = False
        
        self.setup_ui()
        self.start_emulator_search()

    def setup_ui(self):
        # Configurar estilo
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#2c3e50')
        style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1')
        style.configure('TButton', background='#3498db', foreground='#2c3e50', font=('Arial', 9, 'bold'))
        style.configure('TLabelframe', background='#2c3e50', foreground='#ecf0f1')
        style.configure('TLabelframe.Label', background='#2c3e50', foreground='#f1c40f')
        style.map('TButton', background=[('active', '#2980b9')])
        
        # Marco principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Cabecera
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(
            header_frame, 
            text="ADVANCED SNIPER TOOL",
            font=("Arial", 16, "bold"),
            foreground="#f1c40f"
        )
        title_label.pack(side=tk.LEFT, padx=10)
        
        # Indicador de estado
        self.status_indicator = tk.Canvas(header_frame, width=25, height=25, bd=0, highlightthickness=0, bg='#2c3e50')
        self.status_indicator.pack(side=tk.RIGHT, padx=10)
        self.draw_indicator("red")
        
        # Panel de estado
        status_frame = ttk.LabelFrame(main_frame, text="Estado del Sistema")
        status_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Emulador
        emu_frame = ttk.Frame(status_frame)
        emu_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(emu_frame, text="Emulador:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.emulator_status = ttk.Label(emu_frame, text="Buscando...", font=("Arial", 10))
        self.emulator_status.pack(side=tk.LEFT, padx=5)
        
        # Memoria
        mem_frame = ttk.Frame(status_frame)
        mem_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mem_frame, text="Estado Memoria:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.mem_status = ttk.Label(mem_frame, text="No escaneada", font=("Arial", 10))
        self.mem_status.pack(side=tk.LEFT, padx=5)
        
        # Panel de parches
        patches_frame = ttk.LabelFrame(main_frame, text="Parches Disponibles")
        patches_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Canvas y Scrollbar
        canvas = tk.Canvas(patches_frame, bg='#34495e', highlightthickness=0)
        scrollbar = ttk.Scrollbar(patches_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Crear controles para cada patrón
        self.patch_widgets = []
        for pattern in self.patcher.patterns:
            frame = ttk.Frame(self.scrollable_frame)
            frame.pack(fill=tk.X, pady=3, padx=5)
            
            # Nombre del parche
            name_label = ttk.Label(
                frame, 
                text=pattern["name"],
                width=20,
                font=("Arial", 9, "bold")
            )
            name_label.pack(side=tk.LEFT, padx=5)
            
            # Estado del parche
            status_label = ttk.Label(
                frame,
                text="INACTIVO",
                width=8,
                font=("Arial", 9),
                foreground="red"
            )
            status_label.pack(side=tk.LEFT, padx=5)
            
            # Botones
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(side=tk.RIGHT, padx=5)
            
            activate_btn = ttk.Button(
                btn_frame,
                text="ACTIVAR",
                width=8,
                command=lambda p=pattern, s=status_label: self.activate_single(p, s)
            )
            activate_btn.pack(side=tk.LEFT, padx=2)
            
            deactivate_btn = ttk.Button(
                btn_frame,
                text="DESACTIVAR",
                width=8,
                state=tk.DISABLED,
                command=lambda p=pattern, s=status_label: self.deactivate_single(p, s)
            )
            deactivate_btn.pack(side=tk.LEFT, padx=2)
            
            # Guardar referencias
            self.patch_widgets.append({
                "pattern": pattern,
                "status": status_label,
                "activate_btn": activate_btn,
                "deactivate_btn": deactivate_btn
            })
        
        # Barra de progreso
        self.progress = ttk.Progressbar(
            main_frame, 
            orient="horizontal", 
            length=500, 
            mode="indeterminate"
        )
        self.progress.pack(fill=tk.X, pady=10, padx=10)
        
        # Registro de actividad
        log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        self.log_text = tk.Text(
            log_frame, 
            height=8,
            state=tk.DISABLED,
            bg="#34495e",
            fg="#ecf0f1",
            insertbackground="white",
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar_log = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar_log.set)

    def draw_indicator(self, color):
        self.status_indicator.delete("all")
        self.status_indicator.create_oval(5, 5, 20, 20, fill=color, outline="")
        
    def log_message(self, message, color=None):
        tag_name = f"color_{len(self.log_text.tag_names())}"
        if color:
            self.log_text.tag_configure(tag_name, foreground=color)
        
        self.log_text.config(state=tk.NORMAL)
        if color:
            self.log_text.insert(tk.END, message + "\n", tag_name)
        else:
            self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def play_sound(self, sound_type):
        try:
            if sound_type == "success":
                winsound.Beep(1000, 200)
                winsound.Beep(1500, 300)
            elif sound_type == "error":
                winsound.Beep(300, 500)
            elif sound_type == "activate":
                winsound.Beep(1200, 150)
                winsound.Beep(1800, 150)
            elif sound_type == "deactivate":
                winsound.Beep(1800, 150)
                winsound.Beep(1200, 150)
            elif sound_type == "notification":
                winsound.Beep(700, 100)
                winsound.Beep(900, 100)
        except:
            pass

    def start_emulator_search(self):
        if not self.searching:
            self.searching = True
            threading.Thread(target=self.update_emulator_status, daemon=True).start()

    def update_emulator_status(self):
        prev_pid = None
        while self.searching:
            if self.patcher.find_emulator():
                if self.patcher.pid != prev_pid:
                    status_text = f"{self.patcher.emulator_name} (PID: {self.patcher.pid})"
                    self.emulator_status.config(text=status_text, foreground="#2ecc71")
                    self.draw_indicator("green")
                    
                    if not self.patcher.open_process():
                        self.log_message("[-] Error: Permisos insuficientes. Ejecute como ADMINISTRADOR", "red")
                        self.play_sound("error")
                    else:
                        self.log_message("[+] Proceso de emulador abierto con éxito", "green")
                        self.play_sound("success")
                        prev_pid = self.patcher.pid
            else:
                self.emulator_status.config(text="No detectado", foreground="#e74c3c")
                self.draw_indicator("red")
                if prev_pid:
                    self.log_message("[-] Emulador cerrado. Esperando nuevo proceso...", "#f39c12")
                    prev_pid = None
            time.sleep(2)

    def activate_single(self, pattern, status_label):
        self.progress.start(10)
        self.log_message(f"[*] Buscando patrón: {pattern['name']}...", "#3498db")
        self.play_sound("notification")
        self.mem_status.config(text="Escaneando memoria...", foreground="#f39c12")
        
        threading.Thread(
            target=self._activate_single_thread, 
            args=(pattern, status_label),
            daemon=True
        ).start()

    def _activate_single_thread(self, pattern, status_label):
        if not self.patcher.pid:
            self.log_message("[-] Error: No se encontró emulador en ejecución", "red")
            self.play_sound("error")
            self.progress.stop()
            self.mem_status.config(text="Error: Emulador no detectado", foreground="#e74c3c")
            return
            
        if not self.patcher.open_process():
            self.log_message("[-] Error: No se pudo abrir el proceso. Ejecute como ADMINISTRADOR", "red")
            self.play_sound("error")
            self.progress.stop()
            self.mem_status.config(text="Error: Permisos insuficientes", foreground="#e74c3c")
            return
            
        if self.patcher.patch_memory(pattern, activate=True):
            self.log_message(f"[+] {pattern['name']} ACTIVADO con éxito!", "#2ecc71")
            status_label.config(text="ACTIVO", foreground="#2ecc71")
            self.play_sound("activate")
            self.mem_status.config(text="Memoria modificada", foreground="#2ecc71")
            
            # Actualizar botones
            for widget in self.patch_widgets:
                if widget["pattern"] == pattern:
                    widget["activate_btn"].config(state=tk.DISABLED)
                    widget["deactivate_btn"].config(state=tk.NORMAL)
        else:
            self.log_message(f"[-] ERROR: Patrón no encontrado - {pattern['name']}", "red")
            self.play_sound("error")
            self.mem_status.config(text="Patrón no encontrado", foreground="#e74c3c")
        
        self.progress.stop()

    def deactivate_single(self, pattern, status_label):
        self.progress.start(10)
        self.log_message(f"[*] Restaurando: {pattern['name']}...", "#3498db")
        self.play_sound("notification")
        self.mem_status.config(text="Restaurando memoria...", foreground="#f39c12")
        
        threading.Thread(
            target=self._deactivate_single_thread, 
            args=(pattern, status_label),
            daemon=True
        ).start()

    def _deactivate_single_thread(self, pattern, status_label):
        if self.patcher.patch_memory(pattern, activate=False):
            self.log_message(f"[+] {pattern['name']} DESACTIVADO correctamente", "#2ecc71")
            status_label.config(text="INACTIVO", foreground="#e74c3c")
            self.play_sound("deactivate")
            self.mem_status.config(text="Memoria restaurada", foreground="#2ecc71")
            
            # Actualizar botones
            for widget in self.patch_widgets:
                if widget["pattern"] == pattern:
                    widget["activate_btn"].config(state=tk.NORMAL)
                    widget["deactivate_btn"].config(state=tk.DISABLED)
        else:
            self.log_message(f"[-] ERROR: No se pudo restaurar - {pattern['name']}", "red")
            self.play_sound("error")
            self.mem_status.config(text="Error en restauración", foreground="#e74c3c")
        
        self.progress.stop()

    def on_close(self):
        self.searching = False
        self.root.destroy()

if __name__ == "__main__":
    # Verificar permisos de administrador
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
        
    root = tk.Tk()
    app = SniperToolGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
