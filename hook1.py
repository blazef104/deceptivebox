#!/usr/bin/env python3

from sys import argv
from pandare import Panda, ffi

if len(argv)<2:
    print("Usage {} <process name> <recording name>(optional)".format(argv[1]))
    exit(1)

process_name = argv[1]

rep = argv[2] if len(argv) >= 3 else False

if rep:
    panda = Panda(arch="i386", mem='3G', os="windows", os_version="windows_32_7", extra_args=["-s","-nographic"])
else:
    panda = Panda(arch="i386", mem='3G', os="windows", os_version="windows_32_7", qcow="./win7_32.img", extra_args=["--show-cursor", "-net","none"])
# find the address of the library when the right process is started 
# maybe we can do this just at the first occurrence i.e. when the process starts

si = 0
base = 0 

@panda.cb_guest_hypercall(name="hyper", procname=process_name)
def tt(cpu):
    # # first check if it is cpuid
    # pc = panda.current_pc(cpu)
    # inst = panda.virtual_memory_read(cpu,pc,2, fmt='int') # the endianess is swapped
    # if inst == 0xa20f: # the endianess is swapped
        # now check if it is inspecting the hypervisor bit
    eax = panda.arch.get_reg(cpu, "EAX")
    if eax == 1:
        print("CPUID 0x1")
        #panda.arch.set_reg(cpu, "ECX", ecx^0x80000000) # the endianess is swapped (?)
        panda.arch.set_reg(cpu, "ECX", 0) # the endianess is swapped (?)
        return True
    elif eax == 0x40000000:
        print("CPUID Vendor")
        panda.arch.set_reg(cpu, "ECX",0)
        panda.arch.set_reg(cpu, "EDX",0)
    elif eax >= 0x80000002 and eax<=0x80000004:
        print("CPUID Brand")
        panda.arch.set_reg(cpu, "EAX",0)
        panda.arch.set_reg(cpu, "EBX",0)
        panda.arch.set_reg(cpu, "ECX",0)
        panda.arch.set_reg(cpu, "EDX",0)
        return True
    # elif inst == 0x310f:
    #     print("RDTSC")
    return False


#https://superuser.com/questions/625648/virtualbox-how-to-force-a-specific-cpu-to-the-guest


@panda.ppp("syscalls2", "on_NtMapViewOfSection_return", name="ntmap")
def ntmap(cpu, pc, SectionHandle,  ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
    proc = panda.get_process_name(cpu)
    #print("PC 0x{:x}".format(pc))
    print(proc)
    if proc == process_name:

        mappings = panda.get_mappings(cpu)
        for mapping in mappings:
            print(
                "Name: "+ffi.string(mapping.name).decode(),
                "Base: 0x{:x} Size: 0x{:x}".format(mapping.base,mapping.size)
            )
            if ffi.string(mapping.name).decode().lower() == "kernel32.dll":
                global base
                base = mapping.base
                global si
                si = mapping.size
                print("Enabling memory callback")
                panda.enable_callback("cb1")
                print("Enabling hypercall callback")
                panda.enable_callback("hyper")
                print("Disabling MapViewOfSections hook")
                panda.disable_ppp("ntmap")

# this is always active, why?
@panda.cb_virt_mem_before_read(name="cb1", procname=process_name, enabled=False)
def virt_mem_after_read(cpu, pc, addr, size):
    # print("0x{:x}, 0x{:x}".format(base,si))
    if (addr > base and addr < base+si) and base !=0 and si !=0:
        # print("Access at: 0x{:x}".format(addr))
        # print("Hook moved and enabled")
        panda.update_hook("sysinfohook",base+0x53728) # offset of GetSystemInfo
        panda.enable_hook("sysinfohook")
        panda.disable_callback("cb1")
        

@panda.hook(0x0, kernel=False, name="sysinfohook")
def sysinfohook(cpu, tb):
    sp = panda.current_sp(cpu)
    ret = int.from_bytes(panda.virtual_memory_read(cpu,sp,4), byteorder="little", signed=False) # we want to extract the return address so we know that when we reach it the struct that we want to modify will be esp-4
    # print("SP: 0x{:x}".format(sp))
    # print("Ret: 0x{:x}".format(ret))
    panda.update_hook("patchsysinfo",ret)
    panda.enable_hook("patchsysinfo")

@panda.hook(0x0, kernel=False, name="patchsysinfo")
def patchsysinfo(cpu, tb):
    # what we will be reading is a sysinfo structure
    #     typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } DUMMYSTRUCTNAME;
#   } DUMMYUNIONNAME;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO, *LPSYSTEM_INFO;
    sp = panda.current_sp(cpu)
    pstruct = int.from_bytes(panda.virtual_memory_read(cpu, sp - 4, 4), byteorder="little", signed=False)
    # print("Pstruct: 0x{:x}".format(pstruct))
    # we should actually unpack the struct but for the seek of speed and PoC we will access the element with its offset
    # struct = panda.virtual_memory_read(cpu, pstruct+20, 4)
    panda.virtual_memory_write(cpu, pstruct+20, b'\x02')
    print("Number of CPU has been patched!")


# ---------------------------------------------------------------------------------------------------------
# Only used to take recordings of patched sessions
@panda.ppp("hooks2", "on_process_start")
def rec(cpu, procname, asid, pid):
    print(ffi.string(procname).decode())
    if ffi.string(procname).decode() == process_name:
        print(ffi.string(procname).decode()," Started!")
        if not rep:
            panda.run_monitor_cmd("begin_record rec")

# @panda.ppp("hooks2", "on_process_end")
# def end_rec(cpu, procname, asid, pid):
#     if (ffi.string(procname).decode() == process_name) and not rep:
#         panda.disable_callback("hyper")
#         panda.disable_callback("cb1")
#         panda.disable_hook("sysinfohook")
#         panda.disable_hook("patchsysinfo")
#         panda.disable_ppp("ntmap")
#         panda.run_monitor_cmd("end_record")
# ----------------------------------------------------------------------------------------------------------
panda.load_plugin("osi")
panda.load_plugin("hooks2")
panda.load_plugin("syscalls2")
#panda.load_plugin("syscall_hook", {"name": process_name})
panda.load_plugin("timing_patch", {"name": process_name})

panda.enable_memcb()
# not sure if we need this, might introduce some overhead
panda.enable_precise_pc()

panda.disable_callback("hyper")
panda.disable_callback("cb1")

panda.disable_hook("sysinfohook")
panda.disable_hook("patchsysinfo")

if rep:
    panda.run_replay(rep)
else:
    panda.run()
