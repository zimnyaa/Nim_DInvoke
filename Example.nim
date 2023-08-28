import winim
import strformat
import DInvoke

const
  KERNEL32_DLL* = "kernel32.dll"
  NTDLL_DLL* = "ntdll.dll"

type
  VirtualAllocEx_t* = proc (hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}


const
  VirtualAllocEx_FuncName * = "VirtualAllocEx"


let processID = GetCurrentProcessId()
echo "[*] Current Process ID"
echo processID

echo fmt"[*] Calling OpenProcess"
var pHandle = OpenProcess(
    PROCESS_ALL_ACCESS, 
    false, 
    cast[DWORD](processID)
)

echo "[*] pHandle: ", pHandle

var MyVirtualAllocEx = cast[VirtualAllocEx_t](get_function_address(cast[HMODULE](get_library_address(KERNEL32_DLL, FALSE)), VirtualAllocEx_FuncName, 0, FALSE))


echo "[*] Calling VirtualAllocEx via D/Invoke"
let rPtr = MyVirtualAllocEx(
    pHandle,
    NULL,
    cast[SIZE_T](5012),
    MEM_COMMIT,
    PAGE_EXECUTE_READ_WRITE
)
echo "[*] pHandle: ", repr(rPtr)

echo "[*] non-executable library test"
proc `+`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) + cast[uint](b * a[].sizeof))

proc `-`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) - cast[uint](b * a[].sizeof))

let dns = LoadLibraryA("dnsapi.dll")
var
  dosHeader: PIMAGE_DOS_HEADER
  ntHeaders: PIMAGE_NT_HEADERS
  section: PIMAGE_SECTION_HEADER
  memInfo: MEMORY_BASIC_INFORMATION
  oldprotect: DWORD
dosHeader = cast[PIMAGE_DOS_HEADER](dns)
ntHeaders = cast[PIMAGE_NT_HEADERS](cast[int](dns) + dosHeader.e_lfanew)
section = cast[PIMAGE_SECTION_HEADER](cast[int](ntHeaders) + sizeof(IMAGE_NT_HEADERS))
for i in 0..<cast[int](ntHeaders.FileHeader.NumberOfSections):
  let sectionStart: int = cast[int](dns) + cast[PIMAGE_SECTION_HEADER](section + i*sizeof(IMAGE_SECTION_HEADER)).VirtualAddress
  let sectionEnd: int = sectionStart + cast[PIMAGE_SECTION_HEADER](section + i*sizeof(IMAGE_SECTION_HEADER)).Misc.VirtualSize
  var currentAddress = sectionStart
  echo fmt"section start: {currentAddress:#X}"
  while currentAddress < sectionEnd:
    if VirtualQuery(cast[PVOID](currentAddress), addr memInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0:
      raise newException(Exception, "Failed to query memory info")
    echo fmt"protecting current address: {currentAddress:#X}, oldprot:{memInfo.Protect:#X}"
    VirtualProtect(cast[PVOID](currentAddress), cast[int](memInfo.RegionSize), PAGE_READONLY, unsafeAddr oldprotect)
    currentAddress = cast[int](memInfo.BaseAddress) + cast[int](memInfo.RegionSize)

let dnsapi = get_function_address(cast[HMODULE](get_library_address("dnsapi.dll", TRUE)), "DnsQuery_A", 0, FALSE)

echo fmt"DNSQuery_A @{cast[int](dnsapi):#X}"
var consoleInput = readLine(stdin);
