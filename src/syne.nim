import winim, ptr_math
type
    Region* = object
     baseAddress: PVOID
     regionSize: DWORD

    Syne* = object
     processID*: DWORD
     process*: HANDLE


proc toString*[T: CHAR | WCHAR](charlist: openArray[T]): string =
    for character in charlist:
        let char = chr(character)
        if char == '\x00':
            continue
        if char == '\0':
            continue
        result.add(char)


proc findProcessId(procName: string): DWORD =
    var pe32: PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32).DWORD
    var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    Process32First(snapshot, &pe32)

    while Process32Next(snapshot, &pe32) != 0:
        var name = toString[WCHAR](pe32.szExeFile)
        if lstrcmpiA(name, procName) == 0:
            return pe32.th32ProcessID

proc newSyne*(procName: string): Syne =
    let PID = findProcessId(procName)
    let process = OpenProcess(PROCESS_ALL_ACCESS, false, PID)
    result = Syne(
        processID: PID,
        process: process
    )

proc getPID*(syne: Syne): DWORD =
    result = syne.processID

proc getProcessHandle*(syne: Syne): HANDLE =
    result = syne.process

proc getModuleAddress*[T](syne: Syne, modName: string): T =
    var mod32: MODULEENTRY32
    mod32.dwSize = sizeof(MODULEENTRY32).DWORD
    var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, syne.processID)
    Module32First(snapshot, &mod32)
    while Module32Next(snapshot, &mod32) != 0:
        var name = toString[WCHAR](mod32.szModule)
        if lstrcmpiA(name, modName) == 0:
            return cast[T](mod32.modBaseAddr)

proc terminate*(syne: Syne): BOOL =
    result = TerminateProcess(syne.process, 0)

proc read*[T](syne: Syne, address: PVOID): T =
    let process = syne.process
    var buffer: LPVOID = NULL
    var read: SIZE_T 0.SIZE_T
    ReadProcessMemory(
        process,
        address,
        buffer,
        sizeof(T).SIZE_T,
        &read
    )
    result = cast[T](buffer)

proc write*[T](syne: Syne, address: PVOID, val: T): BOOL =
    let process = syne.process
    var written: SIZE_T 0.SIZE_T
    result = WriteProcessMemory(
        process,
        address,
        cast[LPCVOID](&val),
        sizeof(T).SIZE_T,
        &written
    )

# note: this function can be very memory - intensive.

proc search*[T](syne: Syne, val: T): PVOID =
    let process = syne.process
    var address: PVOID = NULL
    var mbi: MEMORY_BASIC_INFORMATION
    while VirtualQueryEx(process, address, &mbi, sizeof(mbi).DWORD) != 0:
        address = cast[PVOID](cast[DWORD_PTR](mbi.BaseAddress) + mbi.RegionSize)
        var data: T = syne.read[T](address)
        if data == val:
            result = address

