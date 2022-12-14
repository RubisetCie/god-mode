/**
 * Execute a command or a program with Trusted Installer privileges.
 * Copyright (C) 2022  Matthieu `Rubisetcie` Carteron
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Windows Vista, the earliest to utilize the Trusted Installer */
#define _WIN32_WINNT _WIN32_WINNT_VISTA

#include <windows.h>
#include <stdio.h>

#define SVC_TRUSTEDINSTALLER L"TrustedInstaller"
#define STR_USAGE L"Usage: %S [/m] [/p] [/q] [/d] [/c <process>] <command/arguments>\n"
#define STR_HELP L"Usage: %S (options) <command/arguments>\n\t[/h]: Show help.\n\t[/m]: Create a new console window.\n\t[/p]: Run the process in parallel.\n\t[/q]: Force surrounding the arguments passed to the process between quotes.\n\t[/d]: Force disabling the quotes surrounding the arguments passed to the process.\n\t[/c]: Run the specified process ('cmd' if no present).\n"

/* For some reason this one is not defined in mingw headers */
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME TEXT("SeDelegateSessionUserImpersonatePrivilege")

/* List of all token privileges */
const wchar_t *tokenPrivileges[35] =
{
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_AUDIT_NAME,
    SE_BACKUP_NAME,
    SE_CHANGE_NOTIFY_NAME,
    SE_CREATE_GLOBAL_NAME,
    SE_CREATE_PAGEFILE_NAME,
    SE_CREATE_PERMANENT_NAME,
    SE_CREATE_SYMBOLIC_LINK_NAME,
    SE_CREATE_TOKEN_NAME,
    SE_DEBUG_NAME,
    SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
    SE_ENABLE_DELEGATION_NAME,
    SE_IMPERSONATE_NAME,
    SE_INC_BASE_PRIORITY_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_LOAD_DRIVER_NAME,
    SE_LOCK_MEMORY_NAME,
    SE_MACHINE_ACCOUNT_NAME,
    SE_MANAGE_VOLUME_NAME,
    SE_PROF_SINGLE_PROCESS_NAME,
    SE_RELABEL_NAME,
    SE_REMOTE_SHUTDOWN_NAME,
    SE_RESTORE_NAME,
    SE_SECURITY_NAME,
    SE_SHUTDOWN_NAME,
    SE_SYNC_AGENT_NAME,
    SE_SYSTEM_ENVIRONMENT_NAME,
    SE_SYSTEM_PROFILE_NAME,
    SE_SYSTEMTIME_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_TCB_NAME,
    SE_TIME_ZONE_NAME,
    SE_TRUSTED_CREDMAN_ACCESS_NAME,
    SE_UNDOCK_NAME,
    SE_UNSOLICITED_INPUT_NAME
};

/* Enable privilege for the given token */
static BOOL enableTokenPrivilege(HANDLE token, const wchar_t *privilege)
{
    TOKEN_PRIVILEGES tp;
    TOKEN_PRIVILEGES prevTp;
    DWORD cbPrev = sizeof(TOKEN_PRIVILEGES);
    LUID luid;

    /* Lookup for the privilege local identifier for the local system */
    if (!LookupPrivilegeValue(NULL, privilege, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    /* Cleanup the current token privileges */
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &prevTp, &cbPrev);

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    prevTp.PrivilegeCount = 1;
    prevTp.Privileges[0].Luid = luid;
    prevTp.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;

    /* Enable the current token privileges */
    AdjustTokenPrivileges(token, FALSE, &prevTp, cbPrev, NULL, NULL);

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    return TRUE;
}

/* Acquire privilege for the current thread */
static BOOL acquirePrivilege(const wchar_t *privilege)
{
    HANDLE token;
    BOOL retry = TRUE;

    REACQUIRE_TOKEN:

    /* Open the access token for the current thread */
    OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token);

    /* If no token found, retry with impersonation */
    if (GetLastError() == ERROR_NO_TOKEN && retry)
    {
        ImpersonateSelf(SecurityImpersonation);
        retry = FALSE;

        goto REACQUIRE_TOKEN;
    }

    if (!enableTokenPrivilege(token, privilege))
        return FALSE;

    return TRUE;
}

/* Set all possible privileges to a token */
static void setAllPrivileges(HANDLE processToken)
{
    /* Iterate over a list to add all privileges to a token */
    size_t i;
    const size_t length = sizeof(tokenPrivileges) / sizeof(*tokenPrivileges);

    for (i = 0; i < length; i++)
        enableTokenPrivilege(processToken, tokenPrivileges[i]);
}

/* Get the Trusted Installer service handle */
static HANDLE getTrustedInstallerHandle(void)
{
    HANDLE scManager, tiService;
    SERVICE_STATUS_PROCESS status = { 0 };
    unsigned long pcb;

    /* Open the Trusted Installer service */
    scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    tiService = OpenService(scManager, SVC_TRUSTEDINSTALLER, SERVICE_START | SERVICE_QUERY_STATUS);

    if (tiService == NULL)
        goto FAILED;

    /* Start the service and wait until it's healthy */
    do
    {
        /* Get the current service state */
        QueryServiceStatusEx(tiService, SC_STATUS_PROCESS_INFO, (unsigned char*)&status, sizeof(SERVICE_STATUS_PROCESS), &pcb);
        
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartService(tiService, 0, NULL))
                goto FAILED;
        }
    }
    while (status.dwCurrentState == SERVICE_STOPPED);

    CloseServiceHandle(scManager);
    CloseServiceHandle(tiService);

    return OpenProcess(PROCESS_CREATE_PROCESS, FALSE, status.dwProcessId);

    FAILED:

    CloseServiceHandle(scManager);
    CloseServiceHandle(tiService);

    return NULL;
}

/* Create process with requested privileges */
static int createProcess(wchar_t *name, BOOL wait, BOOL console)
{
    PROCESS_INFORMATION processInfo = { 0 };
    STARTUPINFOEX startupInfo = { 0 };
    SIZE_T attributeListLength;
    DWORD flags;

    /* Start the Trusted Installer service */
    HANDLE tipHandle = getTrustedInstallerHandle();
    if (tipHandle == NULL)
    {
        fwprintf(stderr, L"Could not open or start the Trusted Installer service!\n");
        return 3;
    }

    /* Handle the process creation flags */
    flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
    if (console)
        flags |= CREATE_NEW_CONSOLE;
    else
        flags |= CREATE_NO_WINDOW;

    /* Initialize startup infos */
    startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
    startupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.StartupInfo.wShowWindow = SW_SHOWNORMAL;

    /* Initialize process attributes */
    InitializeProcThreadAttributeList(NULL, 1, 0, (PSIZE_T)&attributeListLength);

    startupInfo.lpAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListLength);
    InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, (PSIZE_T)&attributeListLength);

    /* Update thread attributes for parent process */
    UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &tipHandle, sizeof(HANDLE), NULL, NULL);

    /* Create the process */
    if (CreateProcess(NULL, name, NULL, NULL, FALSE, flags, NULL, NULL, &startupInfo.StartupInfo, &processInfo))
    {
        HANDLE processToken;

        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

        OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken);
        setAllPrivileges(processToken);

        ResumeThread(processInfo.hThread);

        /* Wait for the process to finish */
        if (wait)
            WaitForSingleObject(processInfo.hProcess, INFINITE);

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);

        /* Success exit */
        return 0;
    }
    else
    {
        fwprintf(stderr, L"Process creation failed. Error code: 0x%08X\n", GetLastError());
        return 4;
    }
}

/* Build the command line with all the arguments */
static wchar_t* createCommand(wchar_t *process, wchar_t **args, size_t len, size_t quotes)
{
    wchar_t *command;
    size_t length = wcslen(process) + 1;
    size_t i;

    /* Compute the length */
    for (i = 0; i < len; i++)
        length += wcslen(args[i]) + quotes;

    /* Copy the full command line */
    command = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length * sizeof(wchar_t));
    wcscpy(command, process);

    for (i = 0; i < len; i++)
    {
        /* Handle the quoting */
        if (quotes > 1)
        {
            wcscat(command, L" \"");
            wcscat(command, args[i]);
            wcscat(command, L"\"");
        }
        else
        {
            wcscat(command, L" ");
            wcscat(command, args[i]);
        }
    }

    return command;
}

/* Entry point */
int wmain(int argc, wchar_t **argv)
{
    /* Variable declaration */
    DWORD mode;
    BOOL console = FALSE;
    BOOL parallel = FALSE;
    BOOL hasProcess = FALSE;
    wchar_t *process = NULL;
    wchar_t *command = NULL;
    size_t argumentStart = 0;
    size_t i;
    int retval;

    /* Argument quotes */
    enum
    {
        AUTO,
        FORCE_ON,
        FORCE_OFF
    } quotes = AUTO;

    /* Parsing command line options */
    for (i = 1; i < argc; i++)
    {
        /* Parse the process to run */
        if (hasProcess)
        {
            hasProcess = FALSE;
            process = argv[i];
            continue;
        }

        /* Check for an at-least-two-character string beginning with '/' or '-' */
        if ((argv[i][0] == L'/' || argv[i][0] == L'-') && argv[i][1] != L'\0' && argumentStart == 0)
        {
            const wchar_t *option = argv[i];
            switch (option[1])
            {
                /* Run the process in parallel (do not wait) */
                case 'p':
                case 'P':
                    parallel = TRUE;
                    break;

                /* Create a new console to host the process */
                case 'm':
                case 'M':
                    console = TRUE;
                    break;

                /* Force surrounding the arguments passed to the process by quotes */
                case 'q':
                case 'Q':
                    quotes = FORCE_ON;
                    break;

                /* Force removing the quotes surrounding the arguments passed to the process */
                case 'd':
                case 'D':
                    quotes = FORCE_OFF;
                    break;

                /* Specify the process to run */
                case 'c':
                case 'C':

                    /* Check if a process has already been specified */
                    if (process)
                    {
                        fwprintf(stderr, L"You can only specify one process to run!\n");
                        break;
                    }

                    /* Check if not the last argument */
                    if (i >= argc - 1)
                    {
                        fwprintf(stderr, L"No process name specified!\n");
                        break;
                    }

                    hasProcess = TRUE;
                    break;

                /* Print usage help */
                case 'h':
                case 'H':
                    wprintf(STR_HELP, argv[0]);
                    return 1;

                default:
                    wprintf(STR_USAGE, argv[0]);
                    return 1;
            }
        }
        else
        {
            /* Starting from now, all the remaining arguments are passed to the created process */
            argumentStart = i;
            break;
        }
    }

    /* If no command specified, run simple "cmd.exe" */
    if (argumentStart == 0)
    {
        const wchar_t *commandName = process ? process : L"cmd.exe";
        if (process)
            commandName = process;
        else
        {
            commandName = L"cmd.exe";

            /* Override the parallel and console flag */
            parallel = TRUE;
            console = TRUE;
        }

        command = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wcslen(commandName) * sizeof(wchar_t));
        wcscpy(command, commandName);
    }
    else
    {
        wchar_t *processName;
        size_t quoting;

        /* If no process was specified, call shell command */
        if (process)
        {
            processName = process;
            quoting = 3;
        }
        else
        {
            processName = L"cmd.exe /C";
            quoting = 1;
        }

        /* Override quoting if specified */
        if (quotes == FORCE_ON)
            quoting = 3;
        else if (quotes == FORCE_OFF)
            quoting = 1;

        command = createCommand(processName, &argv[argumentStart], argc - argumentStart, quoting);
    }

    /* Acquire debug privilege for the current thread */
    if (!acquirePrivilege(SE_DEBUG_NAME))
    {
        fwprintf(stderr, L"Failed to acquire %S!\n", SE_DEBUG_NAME);
        return 2;
    }

    /* Create process with privileges */
    retval = createProcess(command, !parallel, console);

    /* Free the allocated command line */
    HeapFree(GetProcessHeap(), 0, command);

    /* Return */
    return retval;
}
