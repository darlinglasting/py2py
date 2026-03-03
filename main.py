import ctypes
import struct
import subprocess
import sys

kernel = ctypes.windll.kernel32  # good?

kernel.OpenProcess.restype = ctypes.c_void_p
kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]

kernel.VirtualAllocEx.restype = ctypes.c_void_p
kernel.VirtualAllocEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.c_uint32,
]

kernel.WriteProcessMemory.restype = ctypes.c_bool
kernel.WriteProcessMemory.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
]

kernel.VirtualFreeEx.restype = ctypes.c_bool
kernel.VirtualFreeEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
]

kernel.CreateRemoteThread.restype = ctypes.c_void_p
kernel.CreateRemoteThread.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
]

kernel.WaitForSingleObject.restype = ctypes.c_uint32
kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]


def hold(target_proc, blob, access_flag):
    addr = kernel.VirtualAllocEx(target_proc, None, len(blob), 0x3000, access_flag)
    kernel.WriteProcessMemory(target_proc, addr, blob, len(blob), None)
    return addr

# get pid
def pid():
    print("[1] manual")
    print("[2] file drop")
    pick = input("py2py@pick -> ").strip() or "1"
    if pick == "2":
        path = input("drop file path -> ").strip().strip('"')
        flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
        launched = subprocess.Popen([sys.executable, path], creationflags=flags)
        print(f"proc id -> {launched.pid}")
        return launched.pid
    return int(input("proc id -> "))

# get payload
def payload():
    txt = input("payload -> ").strip()
    return (txt + "\n").encode("utf-8") + b"\x00"

# sends the payload
def write(pid, payload):
    dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    mod = ctypes.cdll.LoadLibrary(dll)

    ens = ctypes.cast(mod.PyGILState_Ensure, ctypes.c_void_p).value
    run = ctypes.cast(mod.PyRun_SimpleString, ctypes.c_void_p).value
    rel = ctypes.cast(mod.PyGILState_Release, ctypes.c_void_p).value

    proc = kernel.OpenProcess(0x1F0FFF, False, pid)
    mem = hold(proc, payload, 0x04)

    shell = (
        b"\x48\x83\xEC\x30"
        + b"\x48\xB8"
        + struct.pack("<Q", ens)
        + b"\xFF\xD0"
        + b"\x50"
        + b"\x48\xB9"
        + struct.pack("<Q", mem)
        + b"\x48\xB8"
        + struct.pack("<Q", run)
        + b"\xFF\xD0"
        + b"\x59"
        + b"\x48\xB8"
        + struct.pack("<Q", rel)
        + b"\xFF\xD0"
        + b"\x48\x83\xC4\x30"
        + b"\xC3"
    )

    stub = hold(proc, shell, 0x40)
    thread = kernel.CreateRemoteThread(proc, None, 0, stub, 0, 0, None)
    kernel.WaitForSingleObject(thread, 0xFFFFFFFF)
    kernel.CloseHandle(thread)
    kernel.VirtualFreeEx(proc, stub, 0, 0x8000)
    kernel.VirtualFreeEx(proc, mem, 0, 0x8000)
    kernel.CloseHandle(proc)

target_pid = pid()
while True:
    write(target_pid, payload())
