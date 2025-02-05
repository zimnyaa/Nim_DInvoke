import winim
import tables
import strformat
import algorithm

when defined(WIN64):
  const
    PEB_OFFSET* = 0x30
else:
  const
    PEB_OFFSET* = 0x60


const
  LdrLoadDll_SW2 * = "LdrLoadDll"
  MZ* = 0x5A4D

const
  NTDLL_DLL* = "ntdll.dll"

type
  LdrLoadDll_t* = proc (PathToFile: PWCHAR, Flags: ULONG, ModuleFileName: PUNICODE_STRING, ModuleHandle: PHANDLE): NTSTATUS {.stdcall.}
  




template RVA*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) + cast[ULONG_PTR](rva)))

template RVASub*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) - cast[ULONG_PTR](rva)))

template RVA2VA(casttype, dllbase, rva: untyped): untyped =
  cast[casttype](cast[ULONG_PTR](dllbase) + rva)

proc `+`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) + cast[uint](b * a[].sizeof))

proc `-`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) - cast[uint](b * a[].sizeof))



type
  LDR_DATA_TABLE_ENTRY_N* {.bycopy.} = object
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY
    DllBase*: PVOID
    EntryPoint*: PVOID
    SizeOfImage*: ULONG        ##  in bytes
    FullDllName*: UNICODE_STRING
    BaseDllName*: UNICODE_STRING
    Flags*: ULONG              ##  LDR_*
    LoadCount*: USHORT
    TlsIndex*: USHORT
    HashTableEntry*: LIST_ENTRY
    TimeDateStamp*: ULONG ##     PVOID			LoadedImports;					// seems they are exist only on XP !!!
                        ##     PVOID			EntryPointActivationContext;	// -same-
  PLDR_DATA_TABLE_ENTRY_N* = ptr LDR_DATA_TABLE_ENTRY_N

  PEB_LDR_DATA_N* {.bycopy.} = object
    Length*: ULONG
    Initialized*: BOOLEAN
    SsHandle*: PVOID
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY

  PPEB_LDR_DATA_N* = ptr PEB_LDR_DATA_N

  RTL_DRIVE_LETTER_CURDIR_N* {.bycopy.} = object
    Flags*: USHORT
    Length*: USHORT
    TimeStamp*: ULONG
    DosPath*: UNICODE_STRING

  RTL_USER_PROCESS_PARAMETERS_N* {.bycopy.} = object
    MaximumLength*: ULONG
    Length*: ULONG
    Flags*: ULONG
    DebugFlags*: ULONG
    ConsoleHandle*: PVOID
    ConsoleFlags*: ULONG
    StdInputHandle*: HANDLE
    StdOutputHandle*: HANDLE
    StdErrorHandle*: HANDLE
    CurrentDirectoryPath*: UNICODE_STRING
    CurrentDirectoryHandle*: HANDLE
    DllPath*: UNICODE_STRING
    ImagePathName*: UNICODE_STRING
    CommandLine*: UNICODE_STRING
    Environment*: PVOID
    StartingPositionLeft*: ULONG
    StartingPositionTop*: ULONG
    Width*: ULONG
    Height*: ULONG
    CharWidth*: ULONG
    CharHeight*: ULONG
    ConsoleTextAttributes*: ULONG
    WindowFlags*: ULONG
    ShowWindowFlags*: ULONG
    WindowTitle*: UNICODE_STRING
    DesktopName*: UNICODE_STRING
    ShellInfo*: UNICODE_STRING
    RuntimeData*: UNICODE_STRING
    DLCurrentDirectory*: array[0x20, RTL_DRIVE_LETTER_CURDIR_N]
  PRTL_USER_PROCESS_PARAMETERS_N* = ptr RTL_USER_PROCESS_PARAMETERS_N
  
  PEB_N* {.bycopy.} = object
    InheritedAddressSpace*: BOOLEAN
    ReadImageFileExecOptions*: BOOLEAN
    BeingDebugged*: BOOLEAN
    Spare*: BOOLEAN
    Mutant*: HANDLE
    ImageBaseAddress*: PVOID
    Ldr*: PPEB_LDR_DATA_N
    ProcessParameters*: PRTL_USER_PROCESS_PARAMETERS_N
    SubSystemData*: PVOID
    ProcessHeap*: PVOID
    FastPebLock*: PVOID
    FastPebLockRoutine*: PVOID
    FastPebUnlockRoutine*: PVOID
    EnvironmentUpdateCount*: ULONG
    KernelCallbackTable*: PVOID
    EventLogSection*: PVOID
    EventLog*: PVOID
    FreeList*: PVOID
    TlsExpansionCounter*: ULONG
    TlsBitmap*: PVOID
    TlsBitmapBits*: array[0x2, ULONG]
    ReadOnlySharedMemoryBase*: PVOID
    ReadOnlySharedMemoryHeap*: PVOID
    ReadOnlyStaticServerData*: PVOID
    AnsiCodePageData*: PVOID
    OemCodePageData*: PVOID
    UnicodeCaseTableData*: PVOID
    NumberOfProcessors*: ULONG
    NtGlobalFlag*: ULONG
    Spare2*: array[0x4, BYTE]
    CriticalSectionTimeout*: LARGE_INTEGER
    HeapSegmentReserve*: ULONG
    HeapSegmentCommit*: ULONG
    HeapDeCommitTotalFreeThreshold*: ULONG
    HeapDeCommitFreeBlockThreshold*: ULONG
    NumberOfHeaps*: ULONG
    MaximumNumberOfHeaps*: ULONG
    ProcessHeaps*: ptr PVOID
    GdiSharedHandleTable*: PVOID
    ProcessStarterHelper*: PVOID
    GdiDCAttributeList*: PVOID
    LoaderLock*: PVOID
    OSMajorVersion*: ULONG
    OSMinorVersion*: ULONG
    OSBuildNumber*: ULONG
    OSPlatformId*: ULONG
    ImageSubSystem*: ULONG
    ImageSubSystemMajorVersion*: ULONG
    ImageSubSystemMinorVersion*: ULONG
    GdiHandleBuffer*: array[0x22, ULONG]
    PostProcessInitRoutine*: ULONG
    TlsExpansionBitmap*: ULONG
    TlsExpansionBitmapBits*: array[0x80, BYTE]
    SessionId*: ULONG

  PPEB_N* = ptr PEB_N

proc GetPPEB(p: culong): P_PEB {. 
    header: 
        """#include <windows.h>
           #include <winnt.h>""", 
    importc: "__readgsqword"
.}

{.passC:"-masm=intel".}


## Alternative end

proc is_dll*(hLibrary: PVOID): BOOL
proc get_library_address*(LibName: LPWSTR; DoLoad: BOOL): HANDLE
proc get_function_address*(hLibrary: HMODULE; fname: cstring; ordinal: int, specialCase: BOOL): PVOID

proc is_dll*(hLibrary: PVOID): BOOL =
  var dosHeader: PIMAGE_DOS_HEADER
  var ntHeader: PIMAGE_NT_HEADERS
  if (hLibrary == nil):
    when not defined(release):
        echo "[-] hLibrary == 0, exiting"
    return FALSE
  dosHeader = cast[PIMAGE_DOS_HEADER](hLibrary)
  #echo "Got dos Header"
  ##  check the MZ magic bytes
  if dosHeader.e_magic != MZ:
    when not defined(release):
        echo "[-] No Magic bytes found"
    return FALSE
  ntHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](hLibrary) + dosHeader.e_lfanew)
  #echo "Got NT Headers"
  ##  check the NT_HEADER signature
  if ntHeader.Signature != IMAGE_NT_SIGNATURE:
    when not defined(release):
        echo "[-] Nt Header signature wrong, exiting"
    return FALSE
  var Characteristics: USHORT = ntHeader.FileHeader.Characteristics
  if (Characteristics and IMAGE_FILE_DLL) != IMAGE_FILE_DLL:
    when not defined(release):
        echo "[-] Characteristics shows this is not an DLL, exiting"
    return FALSE
  #echo "Everything fine, this is indeed a DLL"
  return TRUE

proc is_executable(protect: DWORD): bool =
  result = (protect and PAGE_EXECUTE) == PAGE_EXECUTE or 
           (protect and PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ or
           (protect and PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE or
           (protect and PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY

proc scan_sections(hMod: HMODULE): bool =
  var
    dosHeader: PIMAGE_DOS_HEADER
    ntHeaders: PIMAGE_NT_HEADERS
    section: PIMAGE_SECTION_HEADER
    memInfo: MEMORY_BASIC_INFORMATION
  dosHeader = cast[PIMAGE_DOS_HEADER](hMod)
  if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    return false

  ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](hMod) + dosHeader.e_lfanew)
  if ntHeaders.Signature != IMAGE_NT_SIGNATURE:
    return false

  section = cast[PIMAGE_SECTION_HEADER](cast[int](ntHeaders) + sizeof(IMAGE_NT_HEADERS))
  for i in 0..<cast[int](ntHeaders.FileHeader.NumberOfSections):
    let sectionStart: int = cast[int](hMod) + cast[PIMAGE_SECTION_HEADER](section + i*sizeof(IMAGE_SECTION_HEADER)).VirtualAddress
    let sectionEnd: int = sectionStart + cast[PIMAGE_SECTION_HEADER](section + i*sizeof(IMAGE_SECTION_HEADER)).Misc.VirtualSize

    var currentAddress = sectionStart
    while currentAddress < sectionEnd:
      if VirtualQuery(cast[PVOID](currentAddress), addr memInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0:
        raise newException(Exception, "Failed to query memory info")
      echo fmt"current address: {currentAddress:#X}, prot:{memInfo.Protect:#X}"
      if is_executable(memInfo.Protect):
        return true

      currentAddress = cast[int](memInfo.BaseAddress) + cast[int](memInfo.RegionSize)

  return false


##
##  Get the base address of a DLL
##


proc get_library_address*(LibName: LPWSTR; DoLoad: BOOL): HANDLE =
  when not defined(release):
      echo "[*] Parsing the PEB to search for the target DLL"
  var oldpeb = GetPPEB(PEB_OFFSET)
  var Peb: PPEB_N = cast[PPEB_N](GetPPEB(PEB_OFFSET))
  echo fmt"PEB @{cast[int](Peb):#X}"
  var Ldr = Peb.Ldr

  var FirstEntry: PVOID = Ldr.InMemoryOrderModuleList.Blink
  echo fmt"List @{cast[int](Ldr.InMemoryOrderModuleList):#X} against {cast[int](oldpeb.Ldr.InMemoryOrderModuleList):#X}"
  
  echo fmt"FE @{cast[int](FirstEntry):#X} against {cast[int](oldpeb.Ldr.InMemoryOrderModuleList.Blink):#X}"
  var Entry: PLDR_DATA_TABLE_ENTRY_N = cast[PLDR_DATA_TABLE_ENTRY_N](Ldr.InMemoryOrderModuleList.Blink)
  while true:
    # lstrcmpiW is not case sensitive, lstrcmpW is case sensitive
    var compare: int = lstrcmpiW(LibName,cast[LPWSTR](Entry.BaseDllName.Buffer))
    echo "DLL in PEB:", Entry.BaseDllName
    if(compare == 0):
      #echo "DLL names equal"
      if scan_sections(cast[HANDLE](Entry.DllBase)):
        when not defined(release):
          echo fmt"[+] Found the DLL! @{cast[int](Entry.DllBase):#X}"
        return cast[HANDLE](Entry.DllBase)
      else:
        echo "[!] DLL is not executable, freeing..."
        FreeLibrary(cast[HANDLE](Entry.DllBase))
        return get_library_address(LibName, DoLoad)


    Entry = cast[PLDR_DATA_TABLE_ENTRY_N](Entry.InMemoryOrderModuleList.Blink)
    if not (Entry != cast[PLDR_DATA_TABLE_ENTRY_N](cast[int](FirstEntry))): 
      when not defined(release):
          echo "DLL not found for the current proc, loading."
      break
  if (DoLoad == FALSE):
    echo "Exit, loading is not appreciated"
    return 0
  
  var MyLdrLoadDll: LdrLoadDll_t = cast[LdrLoadDll_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(NTDLL_DLL, FALSE)), LdrLoadDll_SW2, 0, TRUE)))
  
  if MyLdrLoadDll == nil:
    echo "[-] Address of LdrLoadDll not found"
    return 0

  var ModuleFileName: UNICODE_STRING
  
  var hLibrary: HANDLE = 0
  
  RtlInitUnicodeString(&ModuleFileName, LibName)
  ##  load the library
  var status: NTSTATUS = MyLdrLoadDll(nil, 0, &ModuleFileName, &hLibrary)
  
  if (status != 0):
    echo fmt"[-] Failed to load {Libname}, status: {status}\n"
    if (hLibrary == 0):
        echo "HLibrary still null"
    return 0
  else:
    echo fmt"Loaded {LibName} successfully!"
  echo fmt"[+] Loaded {LibName} at {hLibrary}"
  return hLibrary


##
##  Find an export in a DLL
##

proc get_function_address*(hLibrary: HMODULE; fname: cstring; ordinal: int, specialCase: BOOL): PVOID =
  var dos: PIMAGE_DOS_HEADER
  var nt: PIMAGE_NT_HEADERS
  #var data: PIMAGE_DATA_DIRECTORY
  var data: array[0..15, IMAGE_DATA_DIRECTORY]
  var exp: PIMAGE_EXPORT_DIRECTORY
  var exp_size: DWORD
  var adr: PDWORD
  var ord: PDWORD
  var functionAddress: PVOID
  var toCheckLibrary: PVOID = cast[PVOID](hLibrary)
  if (is_dll(toCheckLibrary) == FALSE):
    echo "[-] Exiting, not a DLL"
    return nil
  dos = cast[PIMAGE_DOS_HEADER](hLibrary)
  nt = RVA(PIMAGE_NT_HEADERS, cast[PVOID](hLibrary), dos.e_lfanew)
  
  data = nt.OptionalHeader.DataDirectory
  
  if (data[0].Size == 0 or data[0].VirtualAddress == 0):
    echo "[-] Data size == 0 or no VirtualAddress"
    return nil
  exp = RVA(PIMAGE_EXPORT_DIRECTORY, hLibrary, data[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
  exp_size = data[0].Size

  adr = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfFunctions)
  ord = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfNameOrdinals)
  
  functionAddress = nil

  var numofnames = cast[DWORD](exp.NumberOfNames)
  var functions = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)
  var addressOfFunctionsvalue = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)[]
  var names = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfNames)[]

  echo "[*] Checking DLL's Export Directory for the target function"

  if fname != "":
    ##  iterate over all the exports
    #var i: DWORD = 0

    for i in 0 .. numofnames:
      # Getting the function name value
      var funcname = RVA2VA(cstring, cast[PVOID](hLibrary), names)
      
      var finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)
      
      # We are comparing against function names, which include "." because for some reason all function names in this loop also contain references to other DLLs, e.g. "api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory" in kernel32.dll
      var test = StrRStrIA(cast[LPCSTR](funcname),nil,cast[LPCSTR]("."))

      if test != nil:
        # As we found a trash (indirect reference, normally this is in the address field and not in the names field) function, we have to increase this value -> Not an official function
        numofnames = numofnames + 1
      else:
        functions = functions + 1
        addressOfFunctionsvalue = functions[]
      #echo "Relative Address: ", toHex(functions[])
      names += cast[DWORD](len(funcname) + 1)
      #echo "Function: ", funcname
      if fname == funcname:
        
        # So many edge cases, have to investigate
        if (funcname == "CreateFileW"):
          functions = functions - 1
        if (funcname == "SetFileInformationByHandle"):
          functions = functions - 1
        if (funcname == "CloseHandle"):
          functions = functions - 1
        if (funcname == "GetModuleFileNameW"):
          functions = functions - 1

        echo "[+] Found API call: ",funcname
        echo ""
        
        # Strange. For ntdll functions the following is needed, but for kernel32 functions it's not. Don't ask me why. This is a workaround for the moment. Need to troubleshoot.
        if (specialCase):
          # Why?
          echo "This is a special case, subtract one function"
          finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)
        echo "Relative Address: ", toHex(functions[])
        functions = functions - 1
        echo "Relative Address one before: ", toHex(functions[])
        functions = functions + 2
        echo "Relative Address one after: ", toHex(functions[])
        functionAddress = finalfunctionAddress
        break
  else:
    # Add the ordinal number e.g. 1034 for OpenProcess and - the EXP Base address
    echo fmt"Getting address via ordinal: {ordinal}"
    functions = functions + ordinal - 1
    functionAddress = RVA(PVOID, hLibrary, functions[])
    echo "Relative Address: ", toHex(functions[])
    echo "Function address via ordinal:"
    #echo repr(functionAddress)
  if functionAddress == nil:
    return nil
  else:
    return functionAddress