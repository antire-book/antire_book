#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <elf.h>

Elf64_Shdr* find_sections(std::string& p_data, int& p_sec_count, int& p_str_index)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' || p_data[3] != 'F')
    {
        return 0;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);

    Elf64_Off section_offset = ehdr->e_shoff;
    ehdr->e_shoff = 0;

    p_sec_count = ehdr->e_shnum;
    ehdr->e_shnum = 0;

    p_str_index = ehdr->e_shstrndx;
    ehdr->e_shstrndx = 0;

    return reinterpret_cast<Elf64_Shdr*>(&p_data[section_offset]);
}

bool remove_headers(std::string& p_data, Elf64_Shdr* p_sections, int p_sec_count, int p_str_index)
{
    Elf64_Shdr* iter = p_sections;
    for (int i = 0; i < p_sec_count; ++i, ++iter)
    {
        if (iter->sh_link == static_cast<Elf64_Word>(p_str_index))
        {
            std::cout << "A section is still linked to the str index: " << iter->sh_link << std::endl;
            return false;
        }

        if (i == p_str_index)
        {
            memset(&p_data[iter->sh_offset], 0, iter->sh_size);
        }
    }

    memset(p_sections, 0, p_sec_count * sizeof(Elf64_Shdr));
    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./stripBinary <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cout << "Failed to ropen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    int section_count = 0;
    int str_index = 0;
    Elf64_Shdr* sections = find_sections(input, section_count, str_index);
    if (sections == NULL || reinterpret_cast<char*>(sections) > (input.data() + input.length()))
    {
        std::cout << "Failed to find the sections table" << std::endl;
        return EXIT_FAILURE;
    }

    if (!remove_headers(input, sections, section_count, str_index))
    {
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cout << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();
    return EXIT_SUCCESS;
}
