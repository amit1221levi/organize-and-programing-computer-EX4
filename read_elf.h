#ifndef ATAMWET4_READ_ELF_H
#define  ATAMWET4_READ_ELF_H

#define RELOCATABLE_ADDRESS 0
#include "elf64.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/user.h>
#include <signal.h>
#include <syscall.h>
#include <sys/types.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "elf64.h"
#include <stdio.h>

#define ET_REL   1    //Relocatable file.
#define ET_EXEC  2   //Executable.
#define ET_DYN   3    //Shared object.
#define ET_NONE  0   //No file type.
#define ET_CORE  4   //File core.

///===================================================Function===================================================================
unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val);
int get_index(Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *section_name);
char *symbolTableGet(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *stringTableGet(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *getSectionHeaderStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header);
Elf64_Phdr *getProgramHeader(FILE *fp, Elf64_Ehdr *elf_header);
Elf64_Sym *get_symbol(Elf64_Shdr *symbol_table_header, char *string_table, char *symbol_table, char *symbol_input);
unsigned long getRelAddress(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *symbol_name);
void endAll(FILE *fp, char *section_header_string_table, char *symbol_table, char *string_table);
///=============================================================================================================================
#define  PF_X 0x1
#define  PT_LOAD  1
#define  SHF_EXECINSTR  0x4
#define  SHT_STRTAB  3
#define  SHT_SYMTAB  2
#define  STB_GLOBAL  1

//==============================================================getProgramHeader===================================================================
Elf64_Phdr *getProgramHeader(FILE *FP, Elf64_Ehdr *elfHeader)
{
    Elf64_Phdr *program_header = malloc(elfHeader->e_phentsize * elfHeader->e_phnum);
    fseek(FP, elfHeader->e_phoff, SEEK_SET);
    fread(program_header, elfHeader->e_phentsize, elfHeader->e_phnum, FP);
    return program_header;
}

//==============================================================find_symbol=====================================================================
unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val)
{
    if (!symbol_name || !exe_file_name)
    {
        *error_val = -1;
        return 0;
    }
    FILE *fp = fopen(exe_file_name, "r");
    if (fp == NULL)
    {
        *error_val = -3;
        return 0;
    }

    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);
    if (elf_header.e_type != ET_EXEC)
    {
        fclose(fp);
        *error_val = -3;
        return 0;
    }

    Elf64_Shdr section_header[elf_header.e_shentsize * elf_header.e_shnum];
    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(section_header, elf_header.e_shentsize, elf_header.e_shnum, fp);

    char *section_header_string_table = getSectionHeaderStringTable(fp, section_header, &elf_header);

    char *string_table = stringTableGet(fp, section_header, &elf_header, section_header_string_table);

    char *symbolTable = stringTableGet(fp, section_header, &elf_header, section_header_string_table);

    int symtab_index = get_index(section_header, &elf_header, section_header_string_table, ".symtab");
    Elf64_Shdr symbol_table_header = section_header[symtab_index];
    //int num_of_symbols = symbol_table_header.sh_size / symbol_table_header.sh_entsize;
    Elf64_Sym *symbol = get_symbol(&symbol_table_header, string_table, symbolTable, symbol_name);
    if (!symbol)
    {
        *error_val = -1;
        endAll(fp, section_header_string_table, symbolTable, string_table);
        return 0;
    }
    if (ELF64_ST_BIND(symbol->st_info) != STB_GLOBAL)
    {
        *error_val = -2;
        endAll(fp, section_header_string_table, symbolTable, string_table);
        return 0;
    }
    if (symbol->st_shndx == SHN_UNDEF)
    {
        *error_val = -4;
        unsigned long address = getRelAddress(fp, section_header, &elf_header, section_header_string_table, symbol_name);
        endAll(fp, section_header_string_table, symbolTable, string_table);
        return address;
    }

    *error_val = 1;
    endAll(fp, section_header_string_table, symbolTable, string_table);
    return symbol->st_value;
}

//===============================================================symbolTableGet====================================================================
int get_index(Elf64_Shdr *sectionH, Elf64_Ehdr *elf_header, char *section_string_table, char *name)
{
    for (int i = 0; i < elf_header->e_shnum; i++)
    {
        if (strcmp(section_string_table + sectionH[i].sh_name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}
char *symbolTableGet(FILE *fp, Elf64_Shdr *sectionHeader, Elf64_Ehdr *elfHeader, char *section_string_table)
{
    int symtab_index = get_index(sectionHeader, elfHeader, section_string_table, ".symtab");
    Elf64_Shdr symbol_table_header = sectionHeader[symtab_index];
    char *symbol_table = (char *)malloc(symbol_table_header.sh_size);
    fseek(fp, symbol_table_header.sh_offset, SEEK_SET);
    fread(symbol_table, symbol_table_header.sh_size, 1, fp);
    return symbol_table;
}


//=====================================================getSectionHeaderStringTable=======================================================================
char *c(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table)
{
    int strtab_index = get_index(section_header, elf_header, section_header_string_table, ".strtab");
    Elf64_Shdr string_table_header = section_header[strtab_index];
    char *string_table = (char *)malloc(string_table_header.sh_size);
    fseek(fp, string_table_header.sh_offset, SEEK_SET);
    fread(string_table, string_table_header.sh_size, 1, fp);
    return string_table;
}

//==========================================================getSectionHeaderStringTable=========================================================================
char *getSectionHeaderStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header)
{
    Elf64_Shdr header_section_header_string_table = section_header[elf_header->e_shstrndx];
    char *section_header_string_table = (char *)malloc(header_section_header_string_table.sh_size);
    fseek(fp, header_section_header_string_table.sh_offset, SEEK_SET);
    fread(section_header_string_table, header_section_header_string_table.sh_size, 1, fp);
    return section_header_string_table;
}

//=========================================================get_symbol==========================================================================
Elf64_Sym *get_symbol(Elf64_Shdr *symbolHeader, char *string_table, char *symbol_table, char *input)
{
    int num_of_symbols = symbolHeader->sh_size / symbolHeader->sh_entsize;
    Elf64_Sym *ret_symbol = NULL;
    for (int i = 0; i < num_of_symbols; ++i)
    {
        Elf64_Sym *symbol = (Elf64_Sym *)(symbol_table + i * symbolHeader->sh_entsize);
        char *symbol_name = string_table + symbol->st_name;
        if (strcmp(symbol_name, input) == 0)
        {
            if (ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL)
            {
                return symbol;
            }
            ret_symbol = symbol;
        }
    }
    return ret_symbol;
}

//========================================================IndexSymInDynamic===========================================================================
uint32_t IndexSymInDynamic(Elf64_Shdr *dynsym_header, char *dynstr, char *dynsym, char *input)
{
    int num_of_symbols = dynsym_header->sh_size / dynsym_header->sh_entsize;
    Elf64_Sym *ret_symbol = NULL;
    int i = 0;
    for (; i < num_of_symbols; ++i)
    {
        Elf64_Sym *symbol = (Elf64_Sym *)(dynsym + i * dynsym_header->sh_entsize);
        char *symbol_name = dynstr + symbol->st_name;
        if (strcmp(symbol_name,  input) == 0)
        {
            return i;
        }
    }
    return -1;
}

//==========================================================getRelAddress=========================================================================
unsigned long getRelAddress(FILE *fp, Elf64_Shdr *sectionHeader, Elf64_Ehdr *elfHeade, char *sectionHeadString_table, char *symbolName)
{
    int rel_index = get_index(sectionHeader, elfHeade, sectionHeadString_table, ".rela.plt");
    Elf64_Shdr rel_header = sectionHeader[rel_index];
    int dynsym_index = get_index(sectionHeader, elfHeade, sectionHeadString_table, ".dynsym");
    Elf64_Shdr dynsym_header = sectionHeader[dynsym_index];
    int dynstr_index = get_index(sectionHeader, elfHeade, sectionHeadString_table, ".dynstr");
    Elf64_Shdr dynstr_header = sectionHeader[dynstr_index];

    char *dynstr_table = (char *)malloc(dynstr_header.sh_size);
    fseek(fp, dynstr_header.sh_offset, SEEK_SET);
    fread(dynstr_table, dynstr_header.sh_size, 1, fp);

    Elf64_Shdr *dynsym_table = (Elf64_Shdr *)malloc(dynsym_header.sh_size);
    fseek(fp, dynsym_header.sh_offset, SEEK_SET);
    fread(dynsym_table, dynsym_header.sh_size, 1, fp);

    Elf64_Rela *rel_table = (Elf64_Rela *)malloc(rel_header.sh_size);
    fseek(fp, rel_header.sh_offset, SEEK_SET);
    fread(rel_table, rel_header.sh_size, 1, fp);

    int index_of_sym = IndexSymInDynamic(&dynsym_header, dynstr_table, (char *)dynsym_table, symbolName);
    unsigned long got_entry_addr = 0;

    for (int i = 0; i < rel_header.sh_size / rel_header.sh_entsize; ++i)
    {
        Elf64_Rela rel = rel_table[i];
        if (ELF64_R_SYM(rel.r_info) == index_of_sym)
        {
            got_entry_addr = rel.r_offset;
            free(dynstr_table);
            free(dynsym_table);
            free(rel_table);
            return got_entry_addr;
        }
    }
    free(dynstr_table);
    free(dynsym_table);
    free(rel_table);
    return got_entry_addr;
}

//==========================================================endAll=========================================================================

void endAll(FILE *fp, char *section_header_string_table, char *symbol_table, char *string_table)
{
    free(section_header_string_table);
    free(symbol_table);
    free(string_table);
    fclose(fp);
}


#endif  //ATAMWET4_READ_ELF_H




