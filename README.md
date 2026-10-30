# PESymp

English | [Русский](README_RU.md)

- [PESymp](#pesymp)
  - [Preface](#preface)
  - [Building](#building)
    - [Manual build via C# compiler (csc)](#manual-build-via-c-compiler-csc)
    - [Automated build via script](#automated-build-via-script)
  - [Usage](#usage)
  - [Command-line arguments](#command-line-arguments)
    - [Search Options](#search-options)
    - [Patching Options](#patching-options)
    - [Output Options](#output-options)
  - [Usage Examples](#usage-examples)

A utility for finding functions, variables, and symbols in Windows PE binaries and displaying their addresses (RVA, VA, file offset), as well as quick patching of matched locations.

---

## Preface

This utility was inspired by the `symp` tool ([Antibioticss/symp](https://github.com/Antibioticss/symp) and [Drovosek01/symp](https://github.com/Drovosek01/symp)).

I primarily created this tool to obtain `WinVerifyTrust` function addresses in `.exe`, `.dll`, and other PE files without waiting for full analysis in IDA Pro (which takes a noticeable amount of time).

The tool scans export tables, import tables, COFF symbol tables, as well as call and jump instructions (thunks and thunk-calls) in executable sections.

Of course, this utility was developed with the assistance of neural networks.

## Building

The utility is written in C# and has no external dependencies. To build it, you only need the standard C# compiler (`csc`), which comes bundled with the .NET Framework or Visual Studio / Build Tools.

### Manual build via C# compiler (csc)

If the .NET SDK is not installed:
```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /optimize+ /out:pesymp.exe Program.cs
```

If the .NET SDK is installed and `csc.exe` is added to PATH:
```cmd
csc /nologo /optimize+ /out:pesymp.exe Program.cs
```

### Automated build via script

Simply execute `build.ps1` in your terminal:
```powershell
.\build.ps1
```

## Usage

General command syntax:

```cmd
pesymp [options] <symbol> <path to file>
```

Or for direct patching by byte offset:

```cmd
pesymp -x <hex bytes> -- <file offset> <path to file>
```

## Command-line arguments

### Search Options
- `-r` — Treat pattern as a regular expression.
- `-c` — Case-sensitive search (search is case-insensitive by default).
- `-l` — List all symbols (pattern is not required).
- `-t <table>` — Search in a specific table/source. Valid options: `export`, `import`, `coff`, `thunk`, `thunk-call`, `all` (default is `all`). Can be specified multiple times.

### Patching Options
- `-x, --hex <data>` — Patch found offsets (or a specified address) with hex data (case-insensitive, spaces allowed, e.g., `-x "90 90 90"` or `-x 31c0c3`).
- `--` — Delimiter separating option flags from positional arguments (pattern/address and file paths).

### Output Options
- `-q, --quiet` — Quiet mode (outputs addresses only).
- `--addr <type>` — Address type for quiet mode: `rva`, `va`, `offset` (default is `offset`).
- `-n, --names-only` — Output symbol names only (one per line).
- `--no-header` — Suppress table headers.
- `-f <format>` — Output format: `table` (default), `raw`, `csv`, `json`.

## Usage Examples

For experimentation, you can use, for example, a [couple of files](https://mega.nz/file/ciA3QK5Q#PYl7Nrech5uyloguN7DJU_ZQlNQSnUD7UUaCfdMeA4M) from an installed Adobe Premiere Pro 2026 v26.3.2.

Basic search for the `CreateFile` symbol/function in `kernel32.dll`:
```cmd
pesymp.exe CreateFile C:\Windows\System32\kernel32.dll
```

Search for all symbols matching the regex pattern `Api...Buffer`:
```cmd
pesymp.exe -r "Api.*Buffer" app.exe other.dll
```

List all available symbols without applying any filters:
```cmd
pesymp.exe -l app.exe
```

Search for `WinVerifyTrust` via transition tables (thunk) and output its Virtual Address (VA) only:
```cmd
pesymp.exe -t thunk -q --addr va WinVerifyTrust app.exe
```

Export search results to JSON format:
```cmd
pesymp.exe -t export -t import -f json -l app.exe > output.json
```

Patching by matched symbols — Find the `CreateFile` function in `kernel32.dll` and immediately patch its offset with `NOP` bytes (`909090`):
```cmd
pesymp.exe CreateFile kernel32.dll -x 909090
```

Patch a file at a specific direct file offset `0x10002a704` with `NOP` bytes:
```cmd
pesymp.exe -x 909090 -- 0x10002a704 file.exe
```
