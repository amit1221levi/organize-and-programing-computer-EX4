//
// Created by amit levi on 21/01/2023.
//

#ifndef ATAMWET4_HW3_PART1_H
#define ATAMWET4_HW3_PART1_H
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file
#define SYMTAB 2 //i added
#define STRTAB 3
#define LOCAL 0
#define GLOBAL 1

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */


Elf64_Sym * find_helper (char* to_find, Elf64_Sym * symtable, int num, FILE* file,char* str_tab,int* error_val)
{
    int index = -1;

    for (int i = 0; i< num ;i++ )
    {

        char* tmp = str_tab + symtable[i].st_name;
        if (strcmp(to_find,tmp) == 0 && ELF64_ST_BIND(symtable[i].st_info) == GLOBAL)
        {
            if (symtable[i].st_shndx == SHN_UNDEF)
            {
                *error_val = -4;
            }


            return &symtable[i];
        }
        else if (strcmp(to_find,tmp) == 0 && ELF64_ST_BIND(symtable[i].st_info) == LOCAL)
        {
            index = i;
        }


    }

    if (index == -1)
    {
        return NULL;
    }
    else {


        return &symtable[index];
    }
}

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {


    FILE * file = fopen(exe_file_name,"r");
    if (file == NULL)
    {
        *error_val = -3;
        return 0;
    }
    // check type == executable
    Elf64_Ehdr elf;
    fread(&elf, sizeof(Elf64_Ehdr),1,file);

    if (elf.e_type != ET_EXEC)
    {
        *error_val = -3;
        fclose(file);
        return 0;
    }

    fseek(file,elf.e_shoff,0); // added // start of the section
    Elf64_Shdr* shtbl= malloc((elf.e_shentsize)* elf.e_shnum); // tirgoul page 10

    for (int i=0 ; i < elf.e_shnum; i++)
    {
        fread(&shtbl[i],elf.e_shentsize,1,file);
    }


    int sym_index = -1;
    for (int i = 0; i< elf.e_shnum ; i++)
    {

        if (shtbl[i].sh_type == SYMTAB)
        {
            sym_index = i;
            break;
        }
    }
    int str_tab_index = -1;
    Elf64_Shdr shdr;
    fseek(file, elf.e_shoff, 0);
    fread(&shdr, sizeof(Elf64_Shdr), 1, file);

    Elf64_Shdr shstrtab;
    fseek(file, elf.e_shoff + elf.e_shstrndx * sizeof(Elf64_Shdr), 0);
    fread(&shstrtab, sizeof(Elf64_Shdr), 1, file);

    char *shstrtab_tmp = malloc(shstrtab.sh_size);
    fseek(file, shstrtab.sh_offset, 0);
    fread(shstrtab_tmp, shstrtab.sh_size, 1, file);


    Elf64_Shdr strtab;
    for (int i = 0; i < elf.e_shnum; i++)
    {
        fseek(file, elf.e_shoff + i * sizeof(Elf64_Shdr), 0);
        fread(&shdr, sizeof(Elf64_Shdr), 1, file);

        if (strcmp(shstrtab_tmp + shdr.sh_name, ".strtab") == 0)
        {
            strtab = shdr;
        }
    }


    fseek(file,shtbl[sym_index].sh_offset,0); // set seek pointer to start of symtable
    int num = (shtbl[sym_index].sh_size) / (shtbl[sym_index].sh_entsize); // nb of symbols // maybe convert to int from hexa
    Elf64_Sym * symtable = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * num);                 // table of symbols // maybe without (Elf64_Sym *)
    fread(symtable,shtbl[sym_index].sh_size,num,file);         // fill the table
    char* str_tab = (char*) malloc(sizeof(strtab.sh_size));
    fseek(file,strtab.sh_offset,0);
    fread(str_tab,strtab.sh_size,1,file);
    Elf64_Sym * found = find_helper(symbol_name,symtable,num,file,str_tab,error_val); // last parameter is index of strtable
    if (found == NULL)
    {
        *error_val = -1;
        fclose(file);
        free(shtbl);
        free(str_tab);
        free(symtable);
        free(shstrtab_tmp);
        return 0;
    }
    else {

        if (*error_val == -4)
        {
            fclose(file);
            free(shtbl);
            free(str_tab);
            free(symtable);
            free(shstrtab_tmp);
            return 0;
        }

        else if (ELF64_ST_BIND(found->st_info) == GLOBAL)
        {
            *error_val = 1;
            fclose(file);
            free(shtbl);
            free(str_tab);
            free(symtable);
            free(shstrtab_tmp);
            return found->st_value;
        }
        else if (ELF64_ST_BIND(found->st_info) == LOCAL)
        {
            *error_val = -2;
            fclose(file);
            free(shtbl);
            free(str_tab);
            free(symtable);
            free(shstrtab_tmp);
            return 0;



        }

    }

    return 0;
}
/*
int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);



	if (err > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}
*/
#endif //ATAMWET4_HW3_PART1_H
