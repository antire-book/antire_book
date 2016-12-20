#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <elf.h>

/**
 * This tool will cause disassemblers that rely on the sections table for
 * virtual address mapping to fail to correctly find the entry point. This
 * tool expects the provided binary to have no sections table. It will add
 * its own fake table with four sections:
 *
 * - null header
 * - .text: the section the code is in. This will have an altered sh_addr.
 * - .data: the r/w data section
 * - .shstrtab: the strings table.
 *
 * This code makes the assumption that the binary has two PF_LOAD segments in
 * the program table. One segment with PF_X set and one with PF_W set.
 */

/*
 * Edits the ELF header to indicate that there are 4 section headers and that
 * the string table is the last one.
 *
 * \param[in,out] p_data the ELF binary
 * \return true if its possible to add a section table. false otherwise
 */
bool edit_elf_header(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' ||
        p_data[3] != 'F')
    {
        return false;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);

    if (ehdr->e_shoff != 0)
    {
        std::cerr << "The binary already has a section table." << std::endl;
        return false;
    }

    if (ehdr->e_shentsize != sizeof(Elf64_Shdr))
    {
        std::cerr << "Unexpected section header size" << std::endl;
        return false;
    }

    ehdr->e_shoff = p_data.size();
    ehdr->e_shnum = 4;
    ehdr->e_shstrndx = 3;
    return true;
}

/*
 * Finds the PF_X LOAD segment and creates a corresponding section header. The
 * base address is modified to throw off any disassembler that relies on the
 * section header only.
 *
 * \param[in,out] p_data the ELF binary
 * \param[in,out] p_strings the section table string names
 * \return true if no error was encountered
 */
bool add_data_section(std::string& p_data, std::string& p_strings)
{
    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(&p_data[0] + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            if ((phdr->p_flags & PF_X) == PF_X)
            {
                Elf64_Shdr data_header = {};
                data_header.sh_name = p_strings.size();
                data_header.sh_type = SHT_PROGBITS;
                data_header.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
                // "randomly" create a different offset each run
                srand((unsigned)time(0));
                int base = rand() % 250;
                data_header.sh_addr = phdr->p_vaddr + base;
                data_header.sh_offset = phdr->p_offset;
                data_header.sh_size = phdr->p_filesz - base;
                data_header.sh_link = 0;
                data_header.sh_info = 0;
                data_header.sh_addralign = 4;
                data_header.sh_entsize = 0;
                p_strings.append(".text");
                p_strings.push_back('\x00');
                p_data.append(reinterpret_cast<char*>(&data_header),
                              sizeof(data_header));
                return true;
            }
        }
    }
    return false;
}

/*
 * This finds the PF_W segment and creates a matching section header named .data
 *
 * \param[in,out] p_data the ELF binary
 * \param[in,out] p_strings the section table string names
 * \return true if no error was encountered
 */
bool add_text_section(std::string& p_data, std::string& p_strings)
{
    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(&p_data[0] + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++, phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            if ((phdr->p_flags & PF_X) == 0)
            {
                Elf64_Shdr text_header = {};
                text_header.sh_name = p_strings.size();
                text_header.sh_type = SHT_PROGBITS;
                text_header.sh_flags = SHF_ALLOC | SHF_WRITE;
                text_header.sh_addr = phdr->p_vaddr;
                text_header.sh_offset = phdr->p_offset;
                text_header.sh_size = phdr->p_filesz;
                text_header.sh_link = 0;
                text_header.sh_info = 0;
                text_header.sh_addralign = 4;
                text_header.sh_entsize = 0;
                p_strings.append(".data");
                p_strings.push_back('\x00');
                p_data.append(reinterpret_cast<char*>(&text_header),
                              sizeof(text_header));
                return true;
            }
        }
    }
    return false;
}

/**
 * Creates a fake sections table and appends the strings to the end of the file.
 *
 * \param[in,out] p_data the ELF binary
 * \return true on success and false otherwise
 */
bool append_sections(std::string& p_data)
{
    // this will contain the section name strings
    std::string strings;
    strings.push_back('\x00');

    // first section is empty
    Elf64_Shdr null_header = {};
    p_data.append(reinterpret_cast<char*>(&null_header), sizeof(null_header));

    if (!add_data_section(p_data, strings))
    {
        std::cerr << "Failed to find the executable LOAD segment" << std::endl;
        return false;
    }

    if (!add_text_section(p_data, strings))
    {
        std::cerr << "Failed to find the writable LOAD segment" << std::endl;
        return false;
    }

    // .shstrtab
    Elf64_Shdr strtab = {};
    strtab.sh_name = strings.size();
    strtab.sh_type = SHT_STRTAB;
    strtab.sh_flags = 0;
    strtab.sh_addr = 0;
    strtab.sh_offset = p_data.size() + sizeof(Elf64_Shdr);
    strtab.sh_size = 0;
    strtab.sh_link = 0;
    strtab.sh_info = 0;
    strtab.sh_addralign = 4;
    strtab.sh_entsize = 0;
    strings.append(".shstrtab");
    strings.push_back('\x00');
    strtab.sh_size = strings.size();
    p_data.append(reinterpret_cast<char*>(&strtab), sizeof(strtab));
    p_data.append(strings);

    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./fakeHeadersHideEntry <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to ropen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    if (!edit_elf_header(input))
    {
        return EXIT_FAILURE;
    }

    if (!append_sections(input))
    {
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cerr << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();
    return EXIT_SUCCESS;
}
