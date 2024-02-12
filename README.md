# SexyStrings

SexyStrings is a Python script designed to analyze executable files for suspicious strings and potential malware indicators. It extracts strings from executable files, identifies suspicious patterns, malicious API calls, and generates an HTML report with the analysis results. Additionally, it provides detailed information about the analyzed files, including file type, size, creation/modification/access times, and cryptographic hashes (SHA256, MD5).

## Features

- **String Extraction**: The script extracts strings from executable files using the `strings` command-line tool.
- **Suspicious String Detection**: It identifies suspicious patterns within the extracted strings, such as URLs, IP addresses, command-line commands, file paths, email addresses, network protocols, cryptographic hashes (MD5, SHA1, SHA256, SHA512), and specific command-line sequences (e.g., `icacls` commands).
- **Malicious API Call Detection**: SexyStrings detects potentially malicious API calls within the extracted strings, including functions commonly used by malware for process manipulation, file operations, registry manipulation, network communication, and code injection.
- **HTML Report Generation**: After analysis, the script generates an HTML report (`StringAnalysis.html`) summarizing the findings, including identified strings, suspicious patterns, malicious API calls, executable files, and detailed file information.
- **Cross-Platform Compatibility Check**: SexyStrings checks the compatibility of the analyzed executable files across different platforms, flagging files that may not be compatible with Other Systems.

## How It Works

1. **String Extraction**: The script utilizes the `strings` command-line tool to extract readable strings from the analyzed executable files.

2. **String Analysis**: It scans through the extracted strings, applying various regular expression patterns to identify suspicious strings and potential indicators of compromise.

3. **API Call Detection**: SexyStrings searches for known malicious API calls within the extracted strings, comparing them against a predefined list of suspicious function names.

4. **File Information Retrieval**: The script collects detailed information about the analyzed executable files, including file type, size, creation/modification/access times, and cryptographic hashes.

5. **HTML Report Generation**: Based on the analysis results and file information, SexyStrings generates an HTML report, providing a comprehensive overview of the analyzed files and any identified threats or anomalies.

## Critical Items Detected

- URLs and IP addresses
- Command-line commands (e.g., `cmd.exe`, `powershell.exe`)
- File paths and filenames
- Email addresses
- Network protocols (e.g., `http://`, `https://`)
- Cryptographic hashes (MD5, SHA1, SHA256, SHA512)
- Specific command-line sequences (e.g., `icacls` commands)
- Malicious API calls commonly used by malware (e.g., process manipulation, file operations, registry manipulation, network communication, code injection)

## File Information

SexyStrings provides the following file information for each analyzed executable:

- File Name
- File Type
- File Size
- Creation Time
- Modification Time
- Access Time
- SHA256 Hash
- MD5 Hash

## Dependencies

- Python 3.x: [Download Python](https://www.python.org/downloads/)
- python-magic: `pip install python-magic`
- python-magic-bin: `pip install python-magic-bin`

## Usage

Follow the instructions in the [Usage](#usage) section of the [README](README.md) to analyze executable files using SexyStrings.

## Usage Examples

To analyze a Windows executable file named `malware.exe`, run the following command: `python SexyStrings.py malware.exe`

## Output Analysis

After running the script, open the generated HTML report (`StringAnalysis.html`) in a web browser to review the analysis results and take appropriate actions based on the findings.

## License

This project is licensed under the [MIT License](LICENSE).


