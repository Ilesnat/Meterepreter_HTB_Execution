# 🎯 Visual Studio C Application

A lightweight Windows C application developed using **Visual Studio**. This project demonstrates core Windows API usage, process enumeration, and basic system interaction.

---
⚠️ **Disclaimer:** This project is for educational purposes only. It is designed to help individuals understand how malware operates so they can better defend against it. Its intended purpose is for Hack the Box or CTF-like events. 
## 📦 Features

- Built using **pure C** and Windows **Win32 API**
- Process enumeration using `Toolhelp32Snapshot`
- Optional: Process handle access and PID discovery
- Easy to extend for advanced system monitoring or reverse engineering tools

---

## 🚀 Getting Started

### ✅ Prerequisites

- Visual Studio (2017 or newer)
- Windows SDK installed
- Windows 10 or higher

### 🛠️ Build Instructions

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/yourproject.git
    cd yourproject
    ```

2. Open the `.sln` file in **Visual Studio**

3. Build the project:
    - Select **Build > Build Solution** (or press `Ctrl+Shift+B`)
    - Set build mode to `Debug` or `Release`

4. Run the executable from Visual Studio or the `./bin` directory

---

## 🧪 Usage

Example usage (from `main()`):

```c
int pid = 0;
ProcessEnumeration(L"notepad.exe", &dwPID, &hProcess, &pid);
printf("Found PID: %d\n", pid);
