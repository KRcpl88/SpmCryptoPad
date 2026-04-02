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
| `sz` | Zero-terminated 8-bit ASCII string (local buffer) | `szTitle`, `szWindowClass` |
| `p` | Pointer (non-string, non-array) | `pBuffer`, `pKey` |
| `psz` | Pointer to 8-bit ASCII null-terminated string | `pszText`, `pszHashKey` |
| `pwsz` | Pointer to wide (`wchar_t`) null-terminated string | `pwszPassword`, `pwszFilename` |
| `dw` | DWORD | `dwBytesRead` |
| `cb` | Count of bytes | `cbFileSize` |
| `c` | Count of elements | `cBlocks`, `cMasks` |
| `rg` | Fixed-size array — used for both local array variables and pointer parameters to fixed-size arrays | `rgBlock`, `rgNonce`, `rgPermutation` |
| `f` | Boolean flag | `fOK` |
| `k_` | Constant | `k_cSpmBlockSizeBytes` |
| `C` | Class prefix | `CSpmBlockCipher64` |
| `m_` | Member variable | `m_prngSBox` |
| `s_` | Static member variable or static method **within a class** | `s_GetKeyWidth` |
| `g_` | Data variable at global or namespace scope | `g_rgTestKey` |

Classes and functions use PascalCase. Resource IDs use standard Win32 prefixes (`IDM_`, `IDD_`, `IDC_`, `IDS_`, `IDI_`).

### Scope resolution

- Always use the global scope resolution operator `::` when calling global/C-runtime functions from inside a class method (e.g., `::memcmp`, `::memcpy`, `::memset`, `::CloseHandle`).
- Always use the enclosing namespace or class name when calling static helper functions defined at namespace scope from inside a class method (e.g., `CryptoPadLibTests::FillTestBlock(...)`).

### Static function and variable scope rules

- Static functions at **global or namespace scope** use plain **PascalCase** with no prefix (e.g., `FillTestBlock`, `InitCipher`).
- Static member functions **within a class** use the `s_` prefix (e.g., `s_GetKeyWidth`, `s_ApplyPermutation`).
- Static data variables at **global or namespace scope** use the `g_` prefix (e.g., `g_rgTestKey`).
- Static data members **within a class** use the `s_` prefix (e.g., `s_rgSBox`).

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

### Variable initialization

All local variables must be initialized at the point of declaration:

- **Fixed-size arrays**: initialize with `= { 0 }` or with explicit data (e.g., `unsigned char rgBuf[128] = { 0 };`).
- **Class/struct objects**: rely on the constructor to initialize all data members. Every class must have a constructor that initializes all data members, either via an initializer list or assignments in the constructor body.
- **Pointers**: initialize with `new`/`new[]` or `nullptr` / `NULL` (e.g., `LPWSTR pwszText = nullptr;`).
- **Integer types** (`int`, `size_t`, `DWORD`, etc.): initialize to `0` (e.g., `size_t i = 0;`).
- **Boolean types**: initialize to `false` (e.g., `bool fOK = false;`).
- **Enum types**: may be initialized to `0` or a named enumerator (e.g., `BLOCK_MODE eMode = NoPermutation;`).

### SAL annotations

All function parameters must be annotated with SAL (Source Annotation Language) to document intent and enable static analysis:

- Use `__in` for non-null scalar inputs (e.g., `__in size_t cbKey`).
- Use `__in_z` for non-null null-terminated 8-bit ASCII string inputs (e.g., `__in_z const char* pszText`).
- Use `__in_z` for non-null null-terminated wide string inputs (e.g., `__in_z LPCWSTR pwszFilename`).
- Use `__in_opt_z` for optional (possibly null) null-terminated string inputs.
- Use `__in_bcount(n)` for non-null input buffers of `n` bytes (e.g., `__in_bcount(cbKey) const unsigned char* rgKey`).
- Use `__in_ecount(n)` for non-null input buffers of `n` elements (e.g., `__in_ecount(k_cSpmBlockSizeBytes) const unsigned char* rgPermutation`).
- Use `__out_bcount(n)` for non-null output buffers of `n` bytes (e.g., `__out_bcount(cbBlock) unsigned char* rgBlock`).
- Use `__out_ecount(n)` for non-null output buffers of `n` elements.
- Use `__inout_bcount(n)` for non-null buffers that are both read and written (e.g., `__inout_bcount(k_cSpmBlockSizeBytes) BYTE* rgNonce`).
- Use `__out` for non-null scalar output parameters (e.g., `__out size_t* pcb`).
- Use `__inout` for non-null pointers that are both read and written (e.g., `__inout SPM_PRNG* pPrng`).

### Buffer safety

- Every function that takes a pointer to a buffer or fixed-size array **must** also accept an explicit size parameter (count of bytes, e.g., `cbBlock`, or count of elements, e.g., `cBlock`) for that buffer.
- The size parameter must have a matching SAL annotation (e.g., `__in size_t cbBlock`).
- The pointer parameter must have a SAL annotation that references the size parameter (e.g., `__out_bcount(cbBlock)`).
- All loops over a buffer must use the size parameter passed in — never a hardcoded constant — to prevent buffer overflows.

### CI

- **build.yml** — Builds solution and runs tests on every push/PR (Release x64)
- **release.yml** — Builds and publishes `CryptoPad.zip` to GitHub Releases on `v*` tags
