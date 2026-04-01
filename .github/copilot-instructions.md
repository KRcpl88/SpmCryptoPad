# Copilot Instructions for CryptoPad

## Build and Test

This is a Visual Studio 2022 C++ solution (MSVC v143 toolset, x64 only). Build with:

```powershell
msbuild CryptoPad.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
```

Tests use the **Microsoft C++ Unit Test Framework** and produce a DLL. Run tests with:

```powershell
vstest.console.exe x64\Release\CryptoPadLibTests.dll
```

Run a single test by name:

```powershell
vstest.console.exe x64\Release\CryptoPadLibTests.dll /Tests:TestGenNonceOutputNotAllZeros
```

## Architecture

CryptoPad is a Win32 desktop notepad that encrypts file contents so plaintext is never persisted to disk.

Three projects, two dependency chains:

```
CryptoPad.exe (Win32 GUI application)
  └─ CryptoPadLib.lib (static library)

CryptoPadLibTests.dll (unit test DLL)
  └─ CryptoPadLib.lib (static library)
```

- **CryptoPadLib** — Core crypto logic. `CSpmBlockCipher64` implements a substitution-permutation cipher with 128-byte blocks and a 16-bit S-box. `CryptoPadUtils` provides nonce generation and hex-to-binary conversion.
- **CryptoPad** — Win32 message-driven GUI (WndProc callback, modal/modeless dialogs, common file dialogs). Encrypts/decrypts files in 128KB blocks using a password-derived key with a per-operation nonce.
- **CryptoPadLibTests** — Unit tests for nonce generation in `GenNonceTests.cpp`.

## Conventions

### Naming

Hungarian notation is used throughout:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `h` | Handle | `hWnd`, `hFile`, `hInst` |
| `sz` | Zero-terminated string | `szTitle`, `szWindowClass` |
| `p` / `psz` | Pointer / pointer to string | `pBuffer`, `pszPassword` |
| `dw` | DWORD | `dwBytesRead` |
| `cb` | Count of bytes | `cbFileSize` |
| `c` | Count of elements | `cBlocks`, `cMasks` |
| `rg` | Fixed-size array | `rgBlock`, `rgNonce` |
| `f` | Boolean flag | `fOK` |
| `k_` | Constant | `k_cSpmBlockSizeBytes` |
| `C` | Class prefix | `CSpmBlockCipher64` |
| `m_` | Member variable | `m_prngSBox` |

Classes and functions use PascalCase. Resource IDs use standard Win32 prefixes (`IDM_`, `IDD_`, `IDC_`, `IDS_`, `IDI_`).

### Error handling

No C++ exceptions. Errors are handled with Win32-style return codes (`BOOL`, `HRESULT`, `INVALID_HANDLE_VALUE`) and `goto`-based cleanup:

```cpp
if (hFile == INVALID_HANDLE_VALUE)
    goto Error;
// ...
Error:
    ::MessageBoxW(nullptr, L"Error", L"Title", MB_OK | MB_ICONERROR);
Done:
    delete[] pBuffer;
    ::CloseHandle(hFile);
```

Debug-only assertions use a custom `ASSERT` macro (defined in `framework.h`) that calls `DebugBreak()`. Compile-time checks use `C_ASSERT`.

### Includes and headers

- `#pragma once` for include guards
- Quotes for project headers: `#include "resource.h"`, `#include "../CryptoPadLib/SpmBlockCipher64.h"`
- Angle brackets for system headers: `#include <windows.h>`
- Precompiled headers are **not used**

### CI

- **build.yml** — Builds solution and runs tests on every push/PR (Release x64)
- **release.yml** — Builds and publishes `CryptoPad.zip` to GitHub Releases on `v*` tags
