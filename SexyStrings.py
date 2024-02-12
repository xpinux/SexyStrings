import re
import subprocess
import magic
import sys
import logging
import os
import hashlib
import webbrowser
import datetime
from collections import defaultdict
import platform

def extract_strings(executable_file):
    try:
        result = subprocess.run(["strings", executable_file], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        logging.error("Error extracting strings: %s", e)
        return []

def identify_suspicious_strings(strings):
    suspicious_patterns = {
        "URLs": re.compile(r'^(?:http:\/\/|www\.|https:\/\/)([^\/]+)', re.IGNORECASE),
        "IP addresses": re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
        "CMD commands": re.compile(r'(cmd\.exe|cmd)\s+([^\n&]+)', re.IGNORECASE),
        "PowerShell commands": re.compile(r'(?:powershell|powershell\.exe)\s+(.+)', re.IGNORECASE),
        "File paths": re.compile(r'\b([^\s]+\.exe)\b', re.IGNORECASE),
        "Email addresses": re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
        "Network protocols": re.compile(r'(\b(?:[a-z]+://)(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+/?[^\s]*\b)', re.IGNORECASE),
        "MD5-SHA1-SHA256-SHA512": re.compile(r'\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})\b', re.IGNORECASE),
        "icals": re.compile(r'icacls\s+\S+\s+\/grant\s+\S+\s+\/T\s+\/C\s+\/Q', re.IGNORECASE),
        "powershell": re.compile(r'\bpowershell\b\s+-Command\s+"([^"]+)"', re.IGNORECASE),
	"cmd": re.compile(r'\bcmd\b\s+\/c\s+echo\s+(.+)', re.IGNORECASE),
	"regedit": re.compile(r'\bregedit\b\s+(.+)', re.IGNORECASE),
	"RegSetValue": re.compile(r'\bRegSetValue\b\s+(.+)', re.IGNORECASE),
	"RegQueryValue": re.compile(r'\bRegQueryValue\b\s+(.+)', re.IGNORECASE),
	"reg add": re.compile(r'\breg\b\s+add\s+(.+)', re.IGNORECASE),
	"reg delete": re.compile(r'\breg\b\s+delete\s+(.+)', re.IGNORECASE),
	"CreateProcess": re.compile(r'\bCreateProcess\b\s+(.+)', re.IGNORECASE),
	"TerminateProcess": re.compile(r'\bTerminateProcess\b\s+(.+)', re.IGNORECASE),
	"taskkill": re.compile(r'\btaskkill\b\s+(.+)', re.IGNORECASE),
	"tasklist": re.compile(r'\btasklist\b', re.IGNORECASE),
	"sc create": re.compile(r'\bsc\b\s+create\s+(.+)', re.IGNORECASE),
	"sc start": re.compile(r'\bsc\b\s+start\s+(.+)', re.IGNORECASE),
	"sc stop": re.compile(r'\bsc\b\s+stop\s+(.+)', re.IGNORECASE),
	"net start": re.compile(r'\bnet\b\s+start\s+(.+)', re.IGNORECASE),
	"net stop": re.compile(r'\bnet\b\s+stop\s+(.+)', re.IGNORECASE),
	"net user": re.compile(r'\bnet\b\s+user\s+(.+)', re.IGNORECASE),
	"CreateFile": re.compile(r'\bCreateFile\b\s+(.+)', re.IGNORECASE),
	"DeleteFile": re.compile(r'\bDeleteFile\b\s+(.+)', re.IGNORECASE),
	"CopyFile": re.compile(r'\bCopyFile\b\s+(.+)', re.IGNORECASE),
	"MoveFile": re.compile(r'\bMoveFile\b\s+(.+)', re.IGNORECASE),
	"mkdir": re.compile(r'\bmkdir\b\s+(.+)', re.IGNORECASE),
	"rmdir": re.compile(r'\brmdir\b\s+(.+)', re.IGNORECASE),
	"socket": re.compile(r'\bsocket\b\s+(.+)', re.IGNORECASE),
	"bind": re.compile(r'\bbind\b\s+(.+)', re.IGNORECASE),
	"connect": re.compile(r'\bconnect\b\s+(.+)', re.IGNORECASE),
	"send": re.compile(r'\bsend\b\s+(.+)', re.IGNORECASE),
	"recv": re.compile(r'\brecv\b\s+(.+)', re.IGNORECASE),
	"GetHostByName": re.compile(r'\bGetHostByName\b\s+(.+)', re.IGNORECASE),
	"GetHostByAddr": re.compile(r'\bGetHostByAddr\b\s+(.+)', re.IGNORECASE),
	"nmap": re.compile(r'\bnmap\b\s+(.+)', re.IGNORECASE),
	"lsass": re.compile(r'\blsass\b', re.IGNORECASE),
	"mimikatz": re.compile(r'\bmimikatz\b\s+(.+)', re.IGNORECASE),
	"hashdump": re.compile(r'\bhashdump\b\s+(.+)', re.IGNORECASE),
	"AES": re.compile(r'\bAES\b\s+(.+)', re.IGNORECASE),
	"RSA": re.compile(r'\bRSA\b\s+(.+)', re.IGNORECASE),
	"encrypt": re.compile(r'\bencrypt\b\s+(.+)', re.IGNORECASE),
	"decrypt": re.compile(r'\bdecrypt\b\s+(.+)', re.IGNORECASE),
	"shellcode": re.compile(r'\bshellcode\b\s+(.+)', re.IGNORECASE),
	"buffer overflow": re.compile(r'\bbuffer\s+overflow\b\s+(.+)', re.IGNORECASE),
	"ROP chain": re.compile(r'\bROP\s+chain\b\s+(.+)', re.IGNORECASE),
	"schtasks": re.compile(r'\bschtasks\b\s+(.+)', re.IGNORECASE),
	"BITSAdmin": re.compile(r'\bBITSAdmin\b\s+(.+)', re.IGNORECASE),
	"wmic": re.compile(r'\bwmic\b\s+(.+)', re.IGNORECASE),
	"vssadmin": re.compile(r'\bvssadmin\b\s+(.+)', re.IGNORECASE),
	"netsh": re.compile(r'\bnetsh\b\s+(.+)', re.IGNORECASE),
	"netsh advfirewall": re.compile(r'\bnetsh\b\s+advfirewall\b\s+(.+)', re.IGNORECASE),
	"netsh wlan": re.compile(r'\bnetsh\b\s+wlan\b\s+(.+)', re.IGNORECASE),
	"wevtutil": re.compile(r'\bwevtutil\b\s+(.+)', re.IGNORECASE),
	"certutil": re.compile(r'\bcertutil\b\s+(.+)', re.IGNORECASE),
	"regsvr32": re.compile(r'\bregsvr32\b\s+(.+)', re.IGNORECASE),
	"wscript": re.compile(r'\bwscript\b\s+(.+)', re.IGNORECASE),
	"cscript": re.compile(r'\bcscript\b\s+(.+)', re.IGNORECASE),
	"ping": re.compile(r'\bping\b\s+(.+)', re.IGNORECASE),
	"tracert": re.compile(r'\btracert\b\s+(.+)', re.IGNORECASE),
	"runas": re.compile(r'\brunas\b\s+(.+)', re.IGNORECASE),
	"takedown": re.compile(r'\btakedown\b\s+(.+)', re.IGNORECASE),
	"-exec": re.compile(r'\-exec\b\s+(.+)', re.IGNORECASE),
	"xcopy": re.compile(r'\bxcopy\b\s+(.+)', re.IGNORECASE),
	"robocopy": re.compile(r'\brobocopy\b\s+(.+)', re.IGNORECASE),
	"cacls": re.compile(r'\bcacls\b\s+(.+)', re.IGNORECASE),
	"takeown": re.compile(r'\btakeown\b\s+(.+)', re.IGNORECASE),
	"attrib": re.compile(r'\battrib\b\s+(.+)', re.IGNORECASE),
	"bcdedit": re.compile(r'\bbcdedit\b\s+(.+)', re.IGNORECASE),
	"whoami": re.compile(r'\bwhoami\b\s+(.+)', re.IGNORECASE),
	"Get-": re.compile(r'\bGet-\b(\S+)', re.IGNORECASE),
        "EncodedCommand": re.compile(r'-EncodedCommand\s+([^\n]+)', re.IGNORECASE),
    }
    suspicious_strings = defaultdict(list)
    for string in strings:
        for pattern_name, pattern in suspicious_patterns.items():
            matches = pattern.findall(string)
            if matches:
                suspicious_strings[pattern_name].extend(matches)
    return suspicious_strings

def identify_malicious_api_calls(strings):
    malicious_api_calls = [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "CryptGenKey", "CryptDecrypt", "CryptEncrypt", "CryptDestroyKey", "CryptImportKey", "CryptAcquireContextA",
        "SetCurrentDirectoryA", "GetCurrentDirectoryA", "GetComputerNameW", "GetFileAttributesW", "GetFileSizeEx",
        "CreateFileA", "DeleteCriticalSection", "CreateServiceA", "CloseServiceHandle", "StartServiceA",
        "OpenServiceA", "SetFileAttributesW", "CopyFileW", "MoveFileW", "DeleteFileW", "CryptEncrypt", "CryptDecrypt",
        "RegCreateKeyExA", "RegSetValueExA", "RegOpenKeyExA", "RegDeleteKeyA", "RegDeleteValueA", "RegEnumKeyExA",
        "RegQueryValueExA", "GetDriveTypeA", "GetDriveTypeW", "FindFirstFileW", "FindNextFileW", "GetVolumeInformationW",
        "SetThreadExecutionState", "ShellExecuteExA", "ShellExecuteExW", "ShellExecuteA", "ShellExecuteW",
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW",
        "HttpOpenRequestA", "HttpOpenRequestW", "InternetReadFile", "InternetReadFileExA", "InternetReadFileExW",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpQueryHeaders", "CreateMutexA", "CreateMutexW",
        "OpenMutexA", "OpenMutexW", "WaitForSingleObject", "CloseHandle", "ExitProcess",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "CreateThread", "GetAsyncKeyState", "WriteFile", 
        "CreateFileMapping", "MapViewOfFile", "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecute", 
        "WinExec", "GetTickCount", "GetLocalTime", "GetSystemTime", "GetTickCount64", "GetSystemTimeAsFileTime",
        "NtCreateThreadEx", "NtCreateProcess", "NtCreateProcessEx", "NtTerminateProcess", "NtWriteVirtualMemory",
        "ZwCreateThreadEx", "ZwCreateProcess", "ZwCreateProcessEx", "ZwTerminateProcess", "ZwWriteVirtualMemory",
        "RtlCreateUserThread", "RtlCreateUserProcess", "RtlCreateUserProcessEx", "RtlCreateUserThreadEx", 
        "RtlExitUserThread", "RtlExitUserProcess", "RtlRemoteCall", "RtlQueueApcWow64Thread", 
        "LdrLoadDll", "LdrGetProcedureAddress", "LdrUnloadDll", "LdrpLoadDll", "LdrpLoadDllInternal", 
        "LdrpLoadImportModule", "LdrpLoadImportModuleIntoProcess", "LdrpGetProcedureAddress", "LdrpGetProcedureAddressForCaller", 
        "LdrpGetProcedureAddressEx", "LdrpGetModuleBase", "LdrpGetModuleName", "LdrpResolveDllName", "LdrpCheckForLoadedDll", 
        "LdrpFindKnownDll", "LdrpMapDll", "LdrpMapDllFullPath", "LdrpHandleTlsData", "LdrpAllocateTls", 
        "LdrpFreeTls", "LdrpAllocateDataTableEntry", "LdrpFreeLoadContext", "LdrpFreeLoadContextAndNotifyLoaded", 
        "LdrpAllocateFileNameBufferIfNeeded", "LdrpFreeFileNameBuffer", "LdrpAllocateModuleEntry", "LdrpFreeModuleEntry", 
        "LdrpAllocateDataTableEntry", "LdrpFreeDataTableEntry", "LdrpAllocateStringRoutine", "LdrpFreeStringRoutine",
        "LdrpAllocatePatchInformation", "LdrpFreePatchInformation"
    ]
    api_calls_to_techniques = {
        "VirtualAllocEx": ["T1055"], "WriteProcessMemory": ["T1055"], "CreateRemoteThread": ["T1055"],
        "CryptGenKey": ["T1022"], "CryptDecrypt": ["T1022"], "CryptEncrypt": ["T1022"], "CryptDestroyKey": ["T1022"], 
        "CryptImportKey": ["T1022"], "CryptAcquireContextA": ["T1022"],
        "SetCurrentDirectoryA": ["T1562"], "GetCurrentDirectoryA": ["T1562"], "GetComputerNameW": ["T1082"], 
        "GetFileAttributesW": ["T1083"], "GetFileSizeEx": ["T1082"],
        "CreateFileA": ["T1106"], "DeleteCriticalSection": ["T1106"], "CreateServiceA": ["T1031"], 
        "CloseServiceHandle": ["T1031"], "StartServiceA": ["T1031"],
        "OpenServiceA": ["T1031"], "SetFileAttributesW": ["T1106"], "CopyFileW": ["T1106"], 
        "MoveFileW": ["T1106"], "DeleteFileW": ["T1107"], "RegCreateKeyExA": ["T1112"], 
        "RegSetValueExA": ["T1112"], "RegOpenKeyExA": ["T1112"], "RegDeleteKeyA": ["T1112"], 
        "RegDeleteValueA": ["T1112"], "RegEnumKeyExA": ["T1112"], "RegQueryValueExA": ["T1112"], 
        "GetDriveTypeA": ["T1086"], "GetDriveTypeW": ["T1086"], "FindFirstFileW": ["T1083"], 
        "FindNextFileW": ["T1083"], "GetVolumeInformationW": ["T1082"],
        "SetThreadExecutionState": ["T1562"], "ShellExecuteExA": ["T1218"], "ShellExecuteExW": ["T1218"], 
        "ShellExecuteA": ["T1218"], "ShellExecuteW": ["T1218"], "InternetOpenA": ["T1193"], 
        "InternetOpenW": ["T1193"], "InternetConnectA": ["T1193"], "InternetConnectW": ["T1193"], 
        "HttpSendRequestA": ["T1193"], "HttpSendRequestW": ["T1193"], "HttpOpenRequestA": ["T1193"], 
        "HttpOpenRequestW": ["T1193"], "InternetReadFile": ["T1193"], "InternetReadFileExA": ["T1193"], 
        "InternetReadFileExW": ["T1193"], "URLDownloadToFileA": ["T1193"], "URLDownloadToFileW": ["T1193"], 
        "WinHttpOpen": ["T1193"], "WinHttpOpenRequest": ["T1193"], "WinHttpSendRequest": ["T1193"], 
        "WinHttpReceiveResponse": ["T1193"], "WinHttpReadData": ["T1193"], "WinHttpQueryHeaders": ["T1193"], 
        "CreateMutexA": ["T1053"], "CreateMutexW": ["T1053"], "OpenMutexA": ["T1053"], "OpenMutexW": ["T1053"], 
        "WaitForSingleObject": ["T1053"], "CloseHandle": ["T1126"], "ExitProcess": ["T1105"],
        "LoadLibraryA": ["T1055"], "LoadLibraryW": ["T1055"], "GetProcAddress": ["T1106"], 
        "CreateThread": ["T1055"], "GetAsyncKeyState": ["T1114"], "WriteFile": ["T1105"], 
        "CreateFileMapping": ["T1055"], "MapViewOfFile": ["T1055"], "CreateProcessA": ["T1033"], 
        "CreateProcessW": ["T1033"], "WinExec": ["T1106"], "ShellExecute": ["T1218"], 
        "GetTickCount": ["T1018"], "GetLocalTime": ["T1018"], "GetSystemTime": ["T1018"], 
        "GetTickCount64": ["T1018"], "GetSystemTimeAsFileTime": ["T1018"],
        "NtCreateThreadEx": ["T1055"], "NtCreateProcess": ["T1055"], "NtCreateProcessEx": ["T1055"], 
        "NtTerminateProcess": ["T1055"], "NtWriteVirtualMemory": ["T1055"],
        "ZwCreateThreadEx": ["T1055"], "ZwCreateProcess": ["T1055"], "ZwCreateProcessEx": ["T1055"], 
        "ZwTerminateProcess": ["T1055"], "ZwWriteVirtualMemory": ["T1055"],
        "RtlCreateUserThread": ["T1055"], "RtlCreateUserProcess": ["T1055"], "RtlCreateUserProcessEx": ["T1055"], 
        "RtlCreateUserThreadEx": ["T1055"], "RtlExitUserThread": ["T1055"], "RtlExitUserProcess": ["T1055"], 
        "RtlRemoteCall": ["T1055"], "RtlQueueApcWow64Thread": ["T1055"], 
        "LdrLoadDll": ["T1129"], "LdrGetProcedureAddress": ["T1129"], "LdrUnloadDll": ["T1129"], 
        "LdrpLoadDll": ["T1129"], "LdrpLoadDllInternal": ["T1129"], "LdrpLoadImportModule": ["T1129"], 
        "LdrpLoadImportModuleIntoProcess": ["T1129"], "LdrpGetProcedureAddress": ["T1129"], 
        "LdrpGetProcedureAddressForCaller": ["T1129"], "LdrpGetProcedureAddressEx": ["T1129"], 
        "LdrpGetModuleBase": ["T1129"], "LdrpGetModuleName": ["T1129"], "LdrpResolveDllName": ["T1129"], 
        "LdrpCheckForLoadedDll": ["T1129"], "LdrpFindKnownDll": ["T1129"], "LdrpMapDll": ["T1129"], 
        "LdrpMapDllFullPath": ["T1129"], "LdrpHandleTlsData": ["T1129"], "LdrpAllocateTls": ["T1129"], 
        "LdrpFreeTls": ["T1129"], "LdrpAllocateDataTableEntry": ["T1129"], "LdrpFreeLoadContext": ["T1129"], 
        "LdrpFreeLoadContextAndNotifyLoaded": ["T1129"], "LdrpAllocateFileNameBufferIfNeeded": ["T1129"], 
        "LdrpFreeFileNameBuffer": ["T1129"], "LdrpAllocateModuleEntry": ["T1129"], "LdrpFreeModuleEntry": ["T1129"], 
        "LdrpAllocateDataTableEntry": ["T1129"], "LdrpFreeDataTableEntry": ["T1129"], "LdrpAllocateStringRoutine": ["T1129"], 
        "LdrpFreeStringRoutine": ["T1129"], "LdrpAllocatePatchInformation": ["T1129"], "LdrpFreePatchInformation": ["T1129"]
    }
    matched_api_calls = []
    for api_call in malicious_api_calls:
        for string in strings:
            if api_call in string:
                matched_api_calls.append((api_call, api_calls_to_techniques.get(api_call, [])))
                break
    return matched_api_calls

def identify_similar_strings(strings, pattern):
    similar_strings = []
    for string in strings:
        if pattern in string:
            similar_strings.append(string)
    return similar_strings

def identify_new_executable_files():
    current_directory = os.getcwd()
    files = [file for file in os.listdir(current_directory) if os.path.isfile(file) and file.endswith('.exe')]
    return files

def analyze_file(executable_file, output_file):
    try:
        strings = extract_strings(executable_file)
        specific_string = "!This program cannot be run in DOS mode."
        specific_strings = identify_similar_strings(strings, specific_string)
        suspicious_strings = identify_suspicious_strings(strings)
        malicious_api_calls = identify_malicious_api_calls(strings)
        file_info = get_file_info(executable_file)
        cross_platform = check_cross_platform(file_info["Type"])
        html_report = generate_html_report(file_info, strings, specific_strings, suspicious_strings, malicious_api_calls, cross_platform)
        save_report_to_file(html_report, output_file)
    except Exception as e:
        logging.error("Error analyzing file: %s", e)

def check_cross_platform(file_type):
    cross_platform_compatibility = True
    if "Windows" in file_type or "Microsoft" in file_type:
      cross_platform_compatibility = False
    return cross_platform_compatibility

def get_file_info(file_path):
    try:
        file_name = os.path.basename(file_path)
        file_type = magic.Magic().from_file(file_path)
        file_size = os.path.getsize(file_path)
        creation_time = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        access_time = datetime.datetime.fromtimestamp(os.path.getatime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
        sha256_digest = sha256_hash.hexdigest()
        md5_digest = md5_hash.hexdigest()
        return {"Name": file_name, 
                "Type": file_type, 
                "Size": file_size,
                "Creation Time": creation_time,
                "Modification Time": modification_time,
                "Access Time": access_time,
                "SHA256": sha256_digest, 
                "MD5": md5_digest}
    except Exception as e:
        logging.error("Error getting file info: %s", e)
        return {}, "Error getting file info: %s" % e

def generate_html_report(file_info, strings, specific_strings, suspicious_strings, malicious_api_calls, cross_platform):
    html_report = "<html><head><style>"
    html_report += "table { border-collapse: collapse; width: 100%; }"
    html_report += "th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }"
    html_report += "th { background-color: #f2f2f2; }"
    html_report += "h2 { color: #333333; }"
    html_report += "h3 { color: #555555; }"
    html_report += "h4 { color: #777777; }"
    html_report += "</style></head><body>"

    # File Information
    html_report += "<h2>File Information</h2>"
    html_report += "<table>"
    html_report += "<tr><th>Attribute</th><th>Value</th></tr>"
    for key, value in file_info.items():
        html_report += f"<tr><td>{key}</td><td>{value}</td></tr>"
    html_report += "</table>"

    # Cross-platform Compatibility
    html_report += f"<h2>Cross-platform Compatibility</h2>"
    html_report += f"<p>{'Compatible' if cross_platform else 'Not Compatible'}</p>"

    # Table of Contents
    html_report += "<h2>Table of Contents</h2>"
    html_report += "<ul>"
    html_report += "<li><a href='#specific_strings'>Specific Strings</a></li>"
    html_report += "<li><a href='#suspicious_strings'>Suspicious Strings</a></li>"
    html_report += "<li><a href='#malicious_api_calls'>Malicious API Calls</a></li>"
    html_report += "<li><a href='#strings'>Extracted Strings</a></li>"
    html_report += "</ul>"

    # Specific Strings
    if specific_strings:
        html_report += "<h2 id='specific_strings'>Specific Strings</h2>"
        html_report += "<ul>"
        for string in specific_strings:
            html_report += f"<li>{string}</li>"
        html_report += "</ul>"

    # Suspicious Strings
    html_report += "<h2 id='suspicious_strings'>Suspicious Strings</h2>"
    for pattern_name, matches in suspicious_strings.items():
        html_report += f"<h3 id='{pattern_name.lower()}'>{pattern_name}</h3>"
        html_report += "<ul>"
        for match in matches:
            html_report += f"<li>{match}</li>"
        html_report += "</ul>"

    # Malicious API Calls
    html_report += "<h2 id='malicious_api_calls'>Malicious API Calls</h2>"
    html_report += "<table>"
    html_report += "<tr><th>API Call</th><th>MITRE ATT&CK Techniques</th></tr>"
    for api_call, techniques in malicious_api_calls:
        html_report += f"<tr><td>{api_call}</td><td>{', '.join(techniques)}</td></tr>"
    html_report += "</table>"


    # Extracted Strings
    html_report += "<h2 id='strings'>Extracted Strings</h2>"
    html_report += "<table>"
    for string in strings:
        html_report += f"<tr><td>{string}</td></tr>"
    html_report += "</table>"

    html_report += "</body></html>"
    return html_report

def save_report_to_file(html_report, output_file):
    with open(output_file, "w") as f:
        f.write(html_report)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analysis.py <infected_file>")
        sys.exit(1)

    executable_file = sys.argv[1]
    output_file = "StringAnalysis.html"
    analyze_file(executable_file, output_file)
    webbrowser.open(output_file)

if __name__ == "__main__":
    main()

