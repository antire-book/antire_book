#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <random>
#include <elf.h>
#include <map>

#include "../../common/crypto/rc4.h"

bool encrypt_functions(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' || p_data[3] != 'F')
    {
        return false;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Shdr* sections = reinterpret_cast<Elf64_Shdr*>(&p_data[ehdr->e_shoff]);
    Elf64_Half sections_count = ehdr->e_shnum;
    Elf64_Shdr* strings_header = reinterpret_cast<Elf64_Shdr*>(&p_data[ehdr->e_shoff] +
        (ehdr->e_shentsize * ehdr->e_shstrndx));
    const char* strings_table = &p_data[strings_header->sh_offset];

    std::map<std::string, Elf64_Addr> encrypt_mappings;

    // find all ".rc4" sections
    Elf64_Shdr* current = sections;
    for (int i = 0; i < sections_count; i++, current++)
    {
        std::string section_name(&strings_table[current->sh_name]);
        if (section_name.find(".rc4_") == 0)
        {
            std::string func_name = "." + section_name.substr(5);
            encrypt_mappings[func_name] = current->sh_offset;
        }
    }

    // find all sections that ".rc4" was referencing
    current = sections;
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < sections_count; i++, current++)
    {
        std::string section_name(&strings_table[current->sh_name]);
        if (encrypt_mappings.find(section_name) != encrypt_mappings.end())
        {
            unsigned char key[128] = { 0 };
            for (std::size_t i = 0; i < sizeof(key); i++)
            {
                key[i] = dist(rd);
            }

            struct rc4_state state = {};
            rc4_init(&state, key, sizeof(key));
            rc4_crypt(&state, reinterpret_cast<unsigned char*>(&p_data[current->sh_offset]),
                      reinterpret_cast<unsigned char*>(&p_data[current->sh_offset]),
                      current->sh_size);
            memcpy(&p_data[encrypt_mappings[section_name]], key, sizeof(key));
            std::cout << "[+] Encrypted 0x" << std::hex << current->sh_offset << std::endl;
        }
    }

    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./encryptSections <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to open the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    encrypt_functions(input);

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
