
#include <stdbool.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdio.h>
#include "elf64.h"
#include <unistd.h>
#include "hw3_part1.h"
#include <stdbool.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>


#define RELOCATABLE_ADDRESS 0

void getArgs( char **funcName,int arg, char *argv[], char **exeFileName);
bool isAtStackAddress(pid_t child_pid, unsigned long stack_address);
void getReturnAddress( unsigned long *retAddress,pid_t childPid, struct user_regs_struct *regs);
void countFunctionOccurence( unsigned long funcAddr, bool Relocatable,pid_t childPid);
pid_t runTarget(char *const argv[]);
long insertBreakpointInFunc(pid_t childPid,unsigned long funcAddress);
void removeBreakpoint( unsigned long funcAddr,pid_t childPid, unsigned long Data);




bool isAtStackAddress(pid_t childPid, unsigned long stackAddress) {

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
    return regs.rsp == stackAddress;
}



pid_t runTarget(char *const arg[]) {
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        if (execv(arg[2], &arg[2]) < 0) {
            perror("execv");
            exit(EXIT_FAILURE);
        }
    }
    else {
        return pid;
    }
}



void countFunctionOccurence(unsigned long funcAddr, bool Relocatable, pid_t childPid) {

    // initialize variables
    int wait_status, calls_counter = 0;
    struct user_regs_struct regs;
    unsigned long ret_address = 0;
    long ret_data = 0;
    unsigned long stack_address = 0;
    unsigned long got_entry_address = 0;
    waitpid(childPid, &wait_status, 0);

    if (Relocatable) {
        got_entry_address = funcAddr;
        funcAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void *) got_entry_address, NULL);
    }

    long first_func_command = insertBreakpointInFunc(childPid, funcAddr);

    // run the program so it would get to the breakpoint
    ptrace(PTRACE_CONT, childPid, NULL, NULL);
    wait(&wait_status);


    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        if (regs.rip - 1 != funcAddr) {

            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid,&wait_status,0);
            continue;
        }


        stack_address = regs.rsp + 8;

        getReturnAddress(&ret_address, childPid, &regs);
        ret_data = insertBreakpointInFunc(childPid, ret_address);
        removeBreakpoint( funcAddr,childPid, first_func_command);
        ptrace(PTRACE_CONT, childPid, NULL, NULL);
        waitpid(childPid,&wait_status,0);

        while (!isAtStackAddress(childPid, stack_address) && WIFSTOPPED(wait_status)) {
            removeBreakpoint( ret_address,childPid, ret_data);
            ptrace(PTRACE_SINGLESTEP, childPid, 0, 0);
            wait(&wait_status);
            ret_data = insertBreakpointInFunc(childPid, ret_address);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid,&wait_status,0);
        }
        if (WIFSTOPPED(wait_status)) {
            calls_counter++;
            ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
            printf("PRF:: run #%d returned with %lu\n", calls_counter, (long int) regs.rax);
            removeBreakpoint( ret_address,childPid, ret_data);
            if (calls_counter == 1 && Relocatable) {
                funcAddr = ptrace(PTRACE_PEEKTEXT, childPid, (void *) got_entry_address, NULL);
            }
            first_func_command = insertBreakpointInFunc(childPid, funcAddr);
            ptrace(PTRACE_CONT, childPid, NULL, NULL);
            waitpid(childPid,&wait_status,0);
        } else {
            printf("We have a problem\n");
        }
    }
}










void removeBreakpoint( unsigned long funcAddr,pid_t childPid, unsigned long Data)
{
    ptrace(PTRACE_POKETEXT, childPid, (void *)funcAddr, (void *)Data);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, childPid, 0, &regs);
}



long insertBreakpointInFunc(pid_t childPid, unsigned long funcAddress) {
    long orig_data;
    long data = ptrace(PTRACE_PEEKTEXT, childPid, (void*)funcAddress, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    //orig_data = data;
    long int_3 = data | 0xCC;
    ptrace(PTRACE_POKETEXT, childPid, (void*)funcAddress, (void*)data_trap);
    return data;
}



void getArgs(char **funcName, int argc, char *argv[], char **exeFileName) {
    if (argc < 3) {
        //fprintf(stderr, "Error: Insufficient arguments provided.\n");
        fprintf(stderr, "Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    } else if (argc > 3) {
        // fprintf(stderr, "Error: Too many arguments provided.\n");
        fprintf(stderr, "Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    *funcName = argv[1];
    *exeFileName = argv[2];
}


void getReturnAddress(unsigned long *retAddress, pid_t childPid, struct user_regs_struct *regs) {
    *retAddress = ptrace(PTRACE_PEEKTEXT, childPid, regs->rsp, NULL);
}

//============================main================================================================================

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
    countFunctionOccurence(addr,  err == -4,child_pid);
    return 0;
}

