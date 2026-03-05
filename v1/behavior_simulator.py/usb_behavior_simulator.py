import os
import time
import winreg
import tempfile
import threading

print("[*] USB Behavior Simulator started")

# -----------------------------
# Create a test file
# -----------------------------
file_path = os.path.join(tempfile.gettempdir(), "usbtrace_testfile.txt")

with open(file_path, "w") as f:
    f.write("USBTrace DFIR test file\n")

print("[+] File created:", file_path)

# -----------------------------
# Create a registry key
# -----------------------------
key_path = r"Software\\USBTraceTest"

try:
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
    winreg.SetValueEx(key, "TestValue", 0, winreg.REG_SZ, "USBTrace")
    winreg.CloseKey(key)

    print("[+] Registry key created")

except Exception as e:
    print("Registry error:", e)

# -----------------------------
# Create a mutex
# -----------------------------
mutex = threading.Lock()

print("[+] Mutex created")

# -----------------------------
# Open system DLLs
# -----------------------------
try:
    os.system("ipconfig > nul")
    print("[+] Executed system command")
except:
    pass

# -----------------------------
# Sleep so memory capture can happen
# -----------------------------
print("[*] Sleeping for 90 seconds... capture memory now")

time.sleep(90)

print("[*] Simulator finished")