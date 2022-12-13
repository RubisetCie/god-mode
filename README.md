# Run Powered
**Run Powered** is a simple and lightweight utility for Windows, to run processes and commands with high level of privileges.

## Usage
The program may be used in two ways:

### From the File Explorer
Double click the executable and grant admin privileges. A command prompt will appear, able to run commands with highest privileges.

### From the Command Prompt
Simply run superUser from the command prompt (preferably one with admin privileges) using the following arguments:

```runpwrd (options) <process/arguments>```

The following options are used:
|  Option |  Description                                                         |
|:-------:|----------------------------------------------------------------------|
| `/h`    | Display the help message.                                            |
| `/m`    | Create a new console window to host the new process.                 |
| `/p`    | Run the given process in parallel (do not wait for completion).      |
| `/q`    | Used to force surrounding arguments with quotes (useful for spaces). |
| `/d`    | Used to force disabling surrounding with quotes for arguments.       |
| `/c`    | Used to specify the process to run (`cmd` if not present).           |

*Note: You can substitue the `/` character commonly used in Windows by the `-` character, more used on Linux!*

## Build

First build the resource file using [GNU Windres](https://www.gnu.org/software/binutils/):

```windres --codepage=65001 -O coff resource.rc resource.res```

You may also omit the icon from the build by defining the following macro:

```windres --codepage=65001 -O coff -DOMIT_ICON resource.rc resource.res```

Then build the executable using [GCC](https://gcc.gnu.org/):

```gcc -municode -std=c99 -g0 -Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections -o runpwrd.exe main.c resource.res```
