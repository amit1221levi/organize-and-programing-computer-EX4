
#include <stdbool.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include "elf64.h"
#include <fcntl.h>
#include "elf64.h"
#include <unistd.h>
#include <string.h>
#include "hw3_part1.h"
#include <stdbool.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>

#define RELOCATABLE_ADDRESS 0

void getArgs( char **funcName,int arg, char *argv[], char **exeFileName);
bool AtStackAddress(pid_t child_pid, unsigned long stack_address);
void getRetAddress( unsigned long *retAddress,pid_t childPid, struct userRegsStruct *regs);
void runFuncCounter( unsigned long funcAddr, bool Relocatable,pid_t childPid);
pid_t runTarget(char *const argv[]);
long putBreakpointInFunc(pid_t childPid,unsigned long funcAddress);
void removeBreakpoint( unsigned long funcAddr,pid_t childPid, unsigned long Data);

//============================getArgs================================================================================
/*
void getArgs( char **funcName,int arg, char *argv[], char **exeFileName)
{
    if (arg != 3)
    {
        printf("Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(1);
    }
    *funcName = argv[1];
    *exeFileName = argv[2];
}
 */
void getArgs(char **funcName, int argc, char *argv[], char **exeFileName) {
    if (argc < 3) {
        fprintf(stderr, "Error: Insufficient arguments provided.\n");
        fprintf(stderr, "Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    } else if (argc > 3) {
        fprintf(stderr, "Error: Too many arguments provided.\n");
        fprintf(stderr, "Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    *funcName = argv[1];
    *exeFileName = argv[2];
}


//============================runTarget================================================================================
/*
pid_t runTarget(char *const arg[])
{
    pid_t pid;

    pid = fork();

    if (pid > 0)
    {
        return pid;
    }
    else if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        if (execv(arg[2], &arg[2]) < 0)
        {
            perror("execv");
            exit(1);
        }
    }
    else
    {
        perror("fork");
        exit(1);
    }
}
 */
pid_t runTarget(char *const arg[]) {
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        if (execv(arg[2], &arg[2]) < 0) {
            perror("execv");
            exit(EXIT_FAILURE);
        }
    }
    return pid;
}




//============================putBreakpointInFunc================================================================================
// TODO: handle the case where the function is not defined in the executable file
/*
long putBreakpointInFunc(pid_t childPid,unsigned long funcAddress)
{
    long data = ptrace(PTRACE_PEEKTEXT, childPid, (void *)funcAddress, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, childPid, (void *)funcAddress, (void *)data_trap);
    return data;
}
 */


//============================removeBreakpoint================================================================================
/*
void removeBreakpoint( unsigned long funcAddr,pid_t childPid, unsigned long Data)
{
    ptrace(PTRACE_POKETEXT, childPid, (void *)funcAddr, (void *)Data);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, childPid, 0, &regs);
}
 */
long putBreakpointInFunc(pid_t childPid, unsigned long funcAddress) {
    long orig_data;
    long data = ptrace(PTRACE_PEEKDATA, childPid, funcAddress, NULL);
    orig_data = data;
    long int_3 = data | 0xCC;
    ptrace(PTRACE_POKEDATA, childPid, funcAddress, int_3);
    return orig_data;
}

//============================AtStackAddress================================================================================
/*
bool AtStackAddress(pid_t childPid, unsigned long stackAddress)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
    if (regs.rsp == stackAddress)
    {
        return true;
    }
    return false;
}
 */
bool AtStackAddress(pid_t childPid, unsigned long stackAddress) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
    return regs.rsp == stackAddress;
}



//============================getRetAddress================================================================================
/*
void getRetAddress( unsigned long *retAddress,pid_t childPid, struct userRegsStruct *regs)
{
    *retAddress = ptrace(PTRACE_PEEKTEXT, childPid, regs->rsp, NULL);
}
 */
void getRetAddress(unsigned long *retAddress, pid_t childPid, struct user_regs_struct *regs) {
    *retAddress = ptrace(PTRACE_PEEKDATA, childPid, regs->rsp, NULL);
}

//============================runFuncCounter================================================================================
/*
void runFuncCounter( unsigned long funcAddr, bool Relocatable,pid_t childPid)
{

    // initialize variables
    int wait_status, calls_counter = 0;
    struct user_regs_struct regs;
    unsigned long ret_address = 0;
    long ret_data = 0;
    unsigned long stack_address = 0;
    unsigned long got_entry_address = 0;
    waitpid(childPid, &wait_status, 0);

    if (is_relocatable)
    {
        got_entry_address = funcAddr;
        funcAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void *)got_entry_address, NULL);
    }
    long first_func_command = putBreakpointInFunc(funcAddr, childPid);

    // run the program so it would get to the breakpoint
    ptrace(PTRACE_CONT, childPid, NULL, NULL);
    wait(&wait_status);
    // waitpid(child_pid, &wait_status, 0);

    while (WIFSTOPPED(wait_status))
    {
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        if (regs.rip - 1 != funcAddr)
        {
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid, &wait_status, 0);
            continue;
        }

        stack_address = regs.rsp + 8;

        getRetAddress(childPid, &regs, &ret_address);
        ret_data = putBreakpointInFunc(ret_address, childPid);
        removeBreakpoint(childPid, funcAddr, first_func_command);
        ptrace(PTRACE_CONT, childPid, NULL, NULL);
        waitpid(childPid, &wait_status, 0);

        while (!AtStackAddress(childPid, stack_address) && WIFSTOPPED(wait_status))
        {
            removeBreakpoint(childPid, ret_address, ret_data);
            ptrace(PTRACE_SINGLESTEP, childPid, 0, 0);
            wait(&wait_status);
            ret_data = putBreakpointInFunc(ret_address, childPid);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid, &wait_status, 0);
        }
        if (WIFSTOPPED(wait_status))
        {
            calls_counter++;
            ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
            printf("PRF:: run #%d returned with %lu\n", calls_counter, (long int)regs.rax);
            removeBreakpoint(childPid, ret_address, ret_data);
            if (calls_counter == 1 && Relocatable)
            {
                funcAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void *)got_entry_address, NULL);
            }
            first_func_command = putBreakpointInFunc(funcAddr, childPid);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid, &wait_status, 0);
        }
        else
        {
            printf("We have a stupid problem\n");
        }
    }
}
 */
void runFuncCounter(unsigned long funcAddr, bool Relocatable, pid_t childPid) {
    // initialize variables
    int wait_status, calls_counter = 0;
    struct user_regs_struct regs;
    unsigned long ret_address = 0;
    long ret_data = 0;
    unsigned long stack_address = 0;
    unsigned long got_entry_address = 0;

    if (Relocatable) {
        got_entry_address = funcAddr;
        funcAddr = ptrace(PTRACE_PEEKDATA, childPid, (void *) got_entry_address, NULL);
    }
    long first_func_command = putBreakpointInFunc(childPid, funcAddr);

    // run the program so it would get to the breakpoint
    ptrace(PTRACE_CONT, childPid, NULL, NULL);
    wait(&wait_status);

    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        if (regs.rip - 1 != funcAddr) {
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            wait(&wait_status);
            continue;
        }

        stack_address = regs.rsp + 8;

        getRetAddress(&ret_address, childPid, &regs);
        ret_data = putBreakpointInFunc(childPid, ret_address);
        removeBreakpoint(childPid, funcAddr, first_func_command);
        ptrace(PTRACE_CONT, childPid, NULL, NULL);
        wait(&wait_status);

        while (!AtStackAddress(childPid, stack_address) && WIFSTOPPED(wait_status)) {
            removeBreakpoint(childPid, ret_address, ret_data);
            ptrace(PTRACE_SINGLESTEP, childPid, 0, 0);
            wait(&wait_status);
            ret_data = putBreakpointInFunc(childPid, ret_address);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            wait(&wait_status);
        }
        if (WIFSTOPPED(wait_status)) {
            calls_counter++;
            ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
            printf("PRF:: run #%d returned with %lu\n", calls_counter, (long int) regs.rax);
            removeBreakpoint(childPid, ret_address, ret_data);
            if (calls_counter == 1 && Relocatable) {
                funcAddr = ptrace(PTRACE_PEEKDATA, childPid, (void *) got_entry_address, NULL);
            }
            first_func_command = putBreakpointInFunc(childPid, funcAddr);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            wait(&wait_status);
        } else {
            printf("We have a problem\n");
        }
    }
}



//============================main================================================================================
/*
int main(int argc, char *argv[])
{
    char *func_name = argv[1];
    char *exe_file_name = argv[2];
    int err = 1;
    unsigned long addr = find_symbol(func_name, exe_file_name, &err);
    if (err == -1)
    {
        printf("PRF:: %s not found!\n", func_name);
        return 0;
    }
    if (err == -2)
    {
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 0;
    }
    if (err == -3)
    {
        printf("PRF:: %s not an executable! :(\n", exe_file_name);
        return 0;
    }
    //  Ndx == UND
    pid_t child_pid = runTarget(argv);
    runFuncCounter(child_pid, addr, err == -4);
    return 0;
}
 */
int main(int argc, char *argv[]) {
    char *func_name;
    char *exe_file_name;

    getArgs(&func_name, argc, argv, &exe_file_name);
    int err = 1;
    unsigned long addr = find_symbol(func_name, exe_file_name, &err);
    if (err == -1) {
        printf("PRF:: %s not found!\n", func_name);
        return 0;
    }
    if (err == -2) {
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 0;
    }
    if (err == -3) {
        printf("PRF:: %s not an executable! :(\n", exe_file_name);
        return 0;
    }
    pid_t child_pid = runTarget(argv);
    runFuncCounter(child_pid, addr, err == -4);
    return 0;
}
