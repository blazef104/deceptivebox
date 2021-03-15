
#include "string.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "syscalls2/syscalls_ext_typedefs.h"

// typedef struct _OBJECT_ATTRIBUTES {
//   uint32_t          Length;
//   uint32_t          RootDirectory;
//   char*             ObjectName;
//   uint32_t          Attributes;
//   void*             SecurityDescriptor;
//   void*             SecurityQualityOfService;
// } OBJECT_ATTRIBUTES;
typedef struct _OBJECT_ATTRIBUTES {
    uint32_t Length;
    uint32_t RootDirectory;
    uint32_t ObjectName;
    // There's more stuff here but we're ignoring it.
} OBJECT_ATTRIBUTES;

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  uint32_t TitleIndex;
  uint32_t Type;
  uint32_t DataLength;
  char Data[200];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;


// typedef struct _VM_COUNTERS   
// {   
//  ULONG PeakVirtualSize;       
//  ULONG VirtualSize;                
//  ULONG PageFaultCount;        
//  ULONG PeakWorkingSetSize;    
//  ULONG WorkingSetSize;           
//  ULONG QuotaPeakPagedPoolUsage;      
//  ULONG QuotaPagedPoolUsage;        
//  ULONG QuotaPeakNonPagedPoolUsage;  
//  ULONG QuotaNonPagedPoolUsage;      
//  ULONG PagefileUsage;              
//  ULONG PeakPagefileUsage;        
// } VM_COUNTERS, * PVM_COUNTERS;


typedef struct _VM_COUNTERS   
{   
 uint32_t PeakVirtualSize;       
 uint32_t VirtualSize;                
 uint32_t PageFaultCount;        
 uint32_t PeakWorkingSetSize;    
 uint32_t WorkingSetSize;           
 uint32_t QuotaPeakPagedPoolUsage;      
 uint32_t QuotaPagedPoolUsage;        
 uint32_t QuotaPeakNonPagedPoolUsage;  
 uint32_t QuotaNonPagedPoolUsage;      
 uint32_t PagefileUsage;              
 uint32_t PeakPagefileUsage;        
} VM_COUNTERS, * PVM_COUNTERS;

//this can be optimized 
uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        panda_virtual_memory_rw(cpu, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

// GLOBAL VARS 
// will use this method for now
uint32_t tpid = 0;
char *tname;

bool check_pid(CPUState *cpu, uint32_t pid, char *procname){
    if (procname == NULL && pid == 0) return 0;
    OsiProc *current = get_current_process(cpu);
    if(procname == NULL){
        if (pid==current->pid) return 1;
        return 0;
    } else {
        if(!strcmp(procname,current->name)) return 1;
        return 0;
    }
}

// Stealing from BluePill

// NtDelayExecution(
//   IN BOOLEAN              Alertable,
//   IN PLARGE_INTEGER       DelayInterval );

void NtDelayExecution_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t Alertable,
    uint32_t DelayInterval
    ){ 
    if (check_pid(cpu,tpid, tname)){
        //printf("%s triggered NtDelayExecution!\n", tname);
        return;
    }
}

//
// NtQueryDirectoryObject(
//   IN HANDLE               DirectoryObjectHandle,
//   OUT POBJDIR_INFORMATION DirObjInformation,
//   IN ULONG                BufferLength,
//   IN BOOLEAN              GetNextIndex,
//   IN BOOLEAN              IgnoreInputIndex,
//   IN OUT PULONG           ObjectIndex,
//   OUT PULONG              DataWritten OPTIONAL );
void NtQueryDirectoryObject_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t DirectoryObjectHandle,
    uint32_t DirObjInformation, //pointer!
    uint32_t BufferLength,
    uint32_t GetNextIndex,
    uint32_t IgnoreInputIndex,
    uint32_t ObjectIndex, //pointer!
    uint32_t DataWritten //pointer, optional!
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQueryDirectoryObject!\n", tname);
        return;
    }
    
}

//
// NtCreateFile(
//   OUT PHANDLE             FileHandle,
//   IN ACCESS_MASK          DesiredAccess,
//   IN POBJECT_ATTRIBUTES   ObjectAttributes,
//   OUT PIO_STATUS_BLOCK    IoStatusBlock,
//   IN PLARGE_INTEGER       AllocationSize OPTIONAL,
//   IN ULONG                FileAttributes,
//   IN ULONG                ShareAccess,
//   IN ULONG                CreateDisposition,
//   IN ULONG                CreateOptions,
//   IN PVOID                EaBuffer OPTIONAL,
//   IN ULONG                EaLength );
void NtCreateFile_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t FileHandle, //pointer!
    uint32_t DesiredAccess, 
    uint32_t ObjectAttributes, //pointer!
    uint32_t IoStatusBlock, //pointer!
    uint32_t AllocationSize, //pointer, optional!
    uint32_t FileAttributes,
    uint32_t ShareAccess,
    uint32_t CreateDisposition,
    uint32_t CreateOptions,
    uint32_t EaBuffer, //pointer, void!
    uint32_t EaLength
    ){ 
    if (check_pid(cpu, tpid, tname)){
        // printf("%s triggered NtCreateFile!\n", tname);
        // OBJECT_ATTRIBUTES tmp;
        // UNICODE_STRING nameBuf;
        // char *name;
        // name = malloc(256*sizeof(char));
        // panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&tmp, sizeof(OBJECT_ATTRIBUTES),0); // read the object from memory
        // panda_virtual_memory_rw(cpu, tmp.ObjectName, (uint8_t *)&nameBuf, sizeof(UNICODE_STRING), 0); // extract the pointer to string
        // guest_wstrncpy(cpu, name, 256, nameBuf.Buffer); // read the string
        // printf("\tName: %s\n", name);
        // free(name);
        return;
    }
    
}


//

// NtEnumerateKey(
//   IN HANDLE               KeyHandle,
//   IN ULONG                Index,
//   IN KEY_INFORMATION_CLASS KeyInformationClass,
//   OUT PVOID               KeyInformation,
//   IN ULONG                Length,
//   OUT PULONG              ResultLength );
void NtEnumerateKey_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t KeyHandle,
    uint32_t Index,
    uint32_t KeyInformationClass,
    uint32_t KeyInformation, // pointer!
    uint32_t Length,
    uint32_t ResultLength //pointer!
    ){ 
    if (check_pid(cpu, tpid, tname)){
        printf("%s triggered NtEnumerateKey!\n", tname);
        // char *info;
        // info = malloc(sizeof(char)*Length);
        // panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&tmp, sizeof(OBJECT_ATTRIBUTES),0); // read the object from memory
        return;
    }
    
}

//
// NtOpenKey(
//   OUT PHANDLE             pKeyHandle,
//   IN ACCESS_MASK          DesiredAccess,
//   IN POBJECT_ATTRIBUTES   ObjectAttributes );
void NtOpenKey_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t pKeyHandle,
    uint32_t DesiredAccess,
    uint32_t ObjectAttributes //pointer!
    // https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtOpenKey!\n", tname);
        OBJECT_ATTRIBUTES tmp;
        UNICODE_STRING nameBuf;
        char *name;
        name = malloc(256*sizeof(char));
        panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&tmp, sizeof(OBJECT_ATTRIBUTES),0); // read the object from memory
        panda_virtual_memory_rw(cpu, tmp.ObjectName, (uint8_t *)&nameBuf, sizeof(UNICODE_STRING), 0); // extract the pointer to string
        guest_wstrncpy(cpu, name, 256, nameBuf.Buffer); // read the string
        //printf("\tName: %s\n", name);
        free(name);
        return;
    }
    
}

//
// NtQueryValueKey(
//   IN HANDLE               KeyHandle,
//   IN PUNICODE_STRING      ValueName,
//   IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
//   OUT PVOID               KeyValueInformation,
//   IN ULONG                Length,
//   OUT PULONG              ResultLength );
void NtQueryValueKey_return(
    CPUState* cpu,
    target_ulong pc,
    uint32_t KeyHandle,
    uint32_t ValueName, //pointer!
    uint32_t KeyValueInformationClass,
    uint32_t KeyValueInformation, //pointer!
    uint32_t Length, // this is sizeof(KeyValueInformation)
    uint32_t ResultLength //pointer! this is useless for us
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQueryValueKey!\n", tname);
        char *name;
        UNICODE_STRING vname;
        name = malloc(1024*sizeof(char));
        // vname = malloc(sizeof(PUNICODE_STRING));
        //printf("[DEBUG] %d %d %d", ValueName, &ValueName, vname);
        panda_virtual_memory_rw(cpu, ValueName, (uint8_t *)&vname, sizeof(UNICODE_STRING), 0); // extract the pointer to string
        guest_wstrncpy(cpu, name, 1024, vname.Buffer); // read the string
        //printf("\tName: %s\n", name);
        if (strcmp(name, "SystemBiosVersion")==0){
            // printf("Buffer Length: %i\n",Length);
            //PPP_REG_CB("syscalls2", on_NtQueryValueKey_return, NtQueryValueKey_return);
            
            // Super hacky way of doing this, we should find out the proper way to edit this part of the memory
            // Oh btw we are arbitrary patching this but should work fine
            
            KEY_VALUE_PARTIAL_INFORMATION rr;
            // if length is > 200 then we have a problem as it is hardcoded to 200. Just change it in the definition of 
            // KEY_VALUE_PARTIAL_INFORMATION if needed 
            panda_virtual_memory_rw(cpu, KeyValueInformation, (uint8_t *)&rr, Length, 0);
            
            // printf("\n");   
            // for(int i=0;i<rr.DataLength;i++){printf("[%i],%x,%c ",i,rr.Data[i],rr.Data[i]);}
            // printf("\n");
            
            // I'm sure there is a better way to handle windows strings formatted in this way
            // but I like shitty code
            if (rr.Data[0]=='B' && rr.Data[8] == 'S'){
                // printf("\n\tPatching BOCHS\n");
                for(int i=0;i<5;i++){
                    char sub[6] = "INTEL";
                    rr.Data[(i*2)] = sub[i];
                }
                panda_virtual_memory_rw(cpu, KeyValueInformation, (uint8_t *)&rr, Length, 1);    
            }
            
                
        }
        free(name);
        return;
    }
    
}

//
// NtYieldExecution();
//
bool NtYieldExecution_return(
    CPUState* cpu,
    target_ulong pc
){
    // Spoiler it will not work
    return 0;
}

//
// NtQueryAttributesFile(
//   IN POBJECT_ATTRIBUTES   ObjectAttributes,
//   OUT PFILE_BASIC_INFORMATION FileAttributes );
void NtQueryAttributesFile_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t ObjectAttributes, //pointer!
    uint32_t FileAttributes //pointer!
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQueryAttributesFile!\n", tname);
        return;
    }
    
}

//
// NtQueryObject(
//   IN HANDLE               ObjectHandle,
//   IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
//   OUT PVOID               ObjectInformation,
//   IN ULONG                Length,
//   OUT PULONG              ResultLength );
void NtQueryObject_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t ObjectHandle,
    uint32_t ObjectInformationClass,
    uint32_t ObjectInformation, //pointer, void!
    uint32_t Length,
    uint32_t ResultLength //pointer!
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQueryObject!\n", tname);
        return;
    }
    
}


// NOT IN SYSCALLS2 
//SHOULD BE!!!
//  NtUserEnumDisplayDevices(
//      PUNICODE_STRING pustrDevice,
//      DWORD iDevNum,
//      PDISPLAY_DEVICEW pDisplayDevice,
//      DWORD dwFlags)
// void NtUserEnumDisplayDevices_enter(
//     CPUState* cpu,
//     target_ulong pc,
//     uint32_t pustrDevice,
//     uint32_t iDevNum,
//     uint32_t pDisplayDevice, //pointer!
//     uint32_t dwFlags
//     ){ 
//     if (check_pid(cpu, tpid, tname)){
//             printf("%s triggered !\n", tname);
//             return;
//         }
//         
//     }
// }

// NOT IN SYSCALLS2
// void NtUserFindWindowEx_enter(
//     CPUState* cpu,
//     target_ulong pc,
    
//     ){ 
//     if (check_pid(cpu, tpid, tname)){
//             printf("%s triggered !\n", tname);
//             return;
//         }
//         
//     }
// }

//

// NtQuerySystemInformation(
//   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
//   OUT PVOID               SystemInformation,
//   IN ULONG                SystemInformationLength,
//   OUT PULONG              ReturnLength OPTIONAL );
void NtQuerySystemInformation_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t SystemInformationClass,
    uint32_t SystemInformation,
    uint32_t SystemInformationLength,
    uint32_t ReturnLength
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQuerySystemInformation!\n", tname);
        return;
    }
    
}

//
// NtQueryInformationProcess(
//   IN HANDLE               ProcessHandle,
//   IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
//   OUT PVOID               ProcessInformation,
//   IN ULONG                ProcessInformationLength,
//   OUT PULONG              ReturnLength );
//http://pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html
void NtQueryInformationProcess_return(
    CPUState* cpu,
    target_ulong pc,
    uint32_t ProcessHandle,
    uint32_t ProcessInformationClass,
    uint32_t ProcessInformation, //pointer!! OUT
    uint32_t ProcessInformationLength,
    uint32_t ReturnLength //pointer!!
    ){ 
    if (check_pid(cpu, tpid, tname)){
        // printf("%s triggered NtQueryInformationProcess!\n", tname);
        // let's ignore the 26 for now -> ProcessWow64Information which will tell you just if the process is running under 64 or 32 bits
        if (ProcessInformationClass != 26){      
            //guest_wstrncpy(cpu, name, 1024, vname.Buffer); // read the string
            if (ProcessInformationClass == 3){ // we probably don't need this right? 
                VM_COUNTERS data;
                panda_virtual_memory_rw(cpu, ProcessInformation, (uint8_t *)&data, 0x2C, 0);
            }
            // else if (ProcessInformationClass == 36){ //SystemContextSwitchInformation

            // }
            // else{
            //     printf("Class: 0x%x\nOutLen: 0x%x\nInLen: 0x%x\n",ProcessInformationClass, ReturnLength, ProcessInformationLength);
            // // char *data;
            // data = malloc(sizeof(char)*ProcessInformationLength+1);
            // panda_virtual_memory_rw(cpu, ProcessInformation, (uint8_t *)data, ProcessInformationLength, 0); // extract the pointer to buffer
            // for (int i=0;i<ProcessInformationLength;i++){
            //     printf("0x%x, %c",data[i],data[i]);
            // }
            // printf("\n");
            // free(data);
            // }
        }
        return;
    }
}


//

void NtQueryPerformanceCounter_enter(
    CPUState* cpu,
    target_ulong pc,
    uint32_t PerformanceCounter,
    uint32_t PerformanceFrequency
    ){ 
    if (check_pid(cpu, tpid, tname)){
        //printf("%s triggered NtQueryPerformanceCounter!\n", tname);
        return;
    }
    
}


// DEBUG

void my_NtReadFile_enter(
        CPUState* cpu,
        target_ulong pc,
        uint32_t FileHandle,
        uint32_t Event,
        uint32_t UserApcRoutine,
        uint32_t UserApcContext,
        uint32_t IoStatusBlock,
        uint32_t Buffer,
        uint32_t BufferLength,
        uint32_t ByteOffset,
        uint32_t Key
        ){
    if (check_pid(cpu, tpid, tname)){
        //printf("TEST: %s triggered NtReadFile!\n", tname);
        return;
    }
//   printf("Not Monitored!\n");
}

// END DEBUG

// begin
bool init_plugin(void *self) {
    printf("\n[-][DEBUG] V0.0.5\n");
    panda_require("osi");
    panda_require("syscalls2");
    if(!init_osi_api()) return false;

    // parsing args
    panda_arg_list *args = panda_get_args("syscall_hook");

    const char *name = panda_parse_string_opt(args, "name", NULL, "Name of the target process"); //get name
    if (name == NULL){
        return;
    }
    
    tpid = panda_parse_uint32(args, "pid", 0); //get pid
    // copy the name into the global var
    if (strlen(name)<3){
        printf("Not a valid name!\n");
        return false;
    }
    tname = malloc(sizeof(char)*(strlen(name)+1));
    strcpy(tname, name);

    panda_free_args(args); //free memory allocated to parse args

    // Registering callbacks
    // to have an efficient execution we should check if the pid or process name is the one that is being monitored before registering each callback. 
    // this should be easy to do in python

    // A quick and dirty way for now is to register every callback and check every time that we have an hit the process name or the pid
    PPP_REG_CB("syscalls2", on_NtDelayExecution_enter, NtDelayExecution_enter);
    PPP_REG_CB("syscalls2", on_NtQueryDirectoryObject_enter, NtQueryDirectoryObject_enter);
    PPP_REG_CB("syscalls2", on_NtOpenKey_enter, NtOpenKey_enter);
    PPP_REG_CB("syscalls2", on_NtCreateFile_enter, NtCreateFile_enter);
    PPP_REG_CB("syscalls2", on_NtEnumerateKey_enter, NtEnumerateKey_enter);
    PPP_REG_CB("syscalls2", on_NtQueryValueKey_return, NtQueryValueKey_return);

    PPP_REG_CB("syscalls2", on_NtYieldExecution_return, NtYieldExecution_return);
    
    PPP_REG_CB("syscalls2", on_NtQueryAttributesFile_enter, NtQueryAttributesFile_enter);
    PPP_REG_CB("syscalls2", on_NtQueryObject_enter, NtQueryObject_enter);
    PPP_REG_CB("syscalls2", on_NtQuerySystemInformation_enter, NtQuerySystemInformation_enter);
    PPP_REG_CB("syscalls2", on_NtQueryInformationProcess_return, NtQueryInformationProcess_return);
    PPP_REG_CB("syscalls2", on_NtQueryPerformanceCounter_enter, NtQueryPerformanceCounter_enter);
    // DEBUG
    //PPP_REG_CB("syscalls2", on_NtReadFile_enter, my_NtReadFile_enter);   
    // END DEBUG

    return true;
}

// end 
void uninit_plugin(void *self) {
    free(tname);
 }