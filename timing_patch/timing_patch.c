#include "panda/plugin.h"
#include "panda/panda_api.h"
#include "panda/plugin_plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "hooks2/hooks2_ppp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *tname;

bool init_plugin(void *self);
void uninit_plugin(void *self);
bool rdtsc(CPUState *cpu, uint64_t val);

bool check_pid(CPUState *cpu, char* procname);
void process_start(CPUState *cpu, const char *procname, target_ulong asid, target_pid_t pid);
void process_end(CPUState *cpu, const char *procname, target_ulong asid, target_pid_t pid);
int rdtsc_patch = 0;

#define EAX ((CPUArchState*)cpu->env_ptr)->regs[R_EAX]
#define EDX ((CPUArchState*)cpu->env_ptr)->regs[R_EDX]

void process_start(
    CPUState *cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid
    ){
        printf("[DEBUG] start procname: %s\n", procname);
        if(strcmp(procname,tname)==0){
            rdtsc_patch = 1;
        }
}

void process_end(
    CPUState *cpu,
    const char *procname,
    target_ulong asid,
    target_pid_t pid
    ){
        printf("[DEBUG] stop procname: %s\n", procname);
        if(strcmp(procname,tname)==0){
            rdtsc_patch = 0;
        }
}

bool check_pid(CPUState *cpu, char *procname){
    if (procname == NULL) return 0;
    OsiProc *current = get_current_process(cpu);
    //printf("[DEBUG] current process: %s\n",current->name);
    if(!strcmp(procname,current->name)) return 1;
    return 0;
}

bool rdtsc(CPUState *cpu, uint64_t val){
    if (rdtsc_patch==1){
        if (check_pid(cpu,tname)){ // we need this here otherwise it will segfault
            printf("%lu\n", val);
            val=val/9000;
            EAX = (uint32_t)(val);
            EDX = (uint32_t)(val >> 32);
            printf("[DEBUG] rdtsc patched!\n");
            return true;
        }
    }
    return false;
}

bool init_plugin(void *self){
    panda_require("osi");
    panda_require("hooks2");
    if(!init_osi_api()) return false;

    // parsing args
    panda_arg_list *args = panda_get_args("timing_patch");

    const char *name = panda_parse_string_opt(args, "name", NULL, "Name of the target process"); //get name
    if (name == NULL){
        return 1;
    }
    // copy the name into the global var
    if (strlen(name)<3){
        printf("Not a valid name!\n");
        return 1;
    }

    tname = malloc(sizeof(char)*(strlen(name)+1));
    strcpy(tname, name);

    panda_free_args(args); //free memory allocated to parse args


    PPP_REG_CB("hooks2", on_process_start, process_start);
    PPP_REG_CB("hooks2", on_process_end, process_end);
    panda_cb pcb = { .rdtsc = rdtsc };
    panda_register_callback(self, PANDA_CB_RDTSC, pcb);
    
    return true;
}

void uninit_plugin(void *self){
    free(tname);
    return ;
}