#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <elf.h>
#include <vector>

/*
 * This tool takes in an ELF binary that has a sections table and uses dynamic
 * linkage and attachs a fake dynamic symbol table at the end of the binary.
 * Then the symbol names in the fake symbol table are mixed. This will cause
 * disassemblers that place too much trust in the sections table, like IDA,
 * to display the wrong symbol name in the disassembly.
 */

/*
 * Finds the SHT_DYNSYM in the sections table, points the offset to the end
 * of the binary, and copies the existing dynsym to the end of the file. Then
 * loops over the symbols in the new dynsym and changes all the name offsets
 * around
 *
 * \param[in,out] p_data the ELF binary we are modifying
 * \return truee if we didn't encounter and error and false otherwise
 */
bool append_dynsym(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' ||
        p_data[3] != 'F')
    {
        std::cerr << "Bad magic." << std::endl;
        return false;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    if (ehdr->e_shoff == 0)
    {
        std::cerr << "The binary has no sections table" << std::endl;
        return false;
    }

    if (ehdr->e_shentsize != sizeof(Elf64_Shdr))
    {
        std::cerr << "Unexpected section header size" << std::endl;
        return false;
    }

    // loop over the sections until we hit .dynsym
    Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(&p_data[0] + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++, shdr++)
    {
        if (shdr->sh_type == SHT_DYNSYM)
        {
            std::size_t offset = shdr->sh_offset;

            // repoint the offset to the end of the file
            shdr->sh_offset = p_data.size();

            // copy the dymsym to the end of the file
            p_data.append(p_data.data() + offset, shdr->sh_size);

            // collects all the string offsets
            std::vector<int> name_offsets;
            std::vector<Elf64_Sym*> symbols;
            Elf64_Sym* symbol = reinterpret_cast<Elf64_Sym*>(&p_data[0] + shdr->sh_offset);
            for ( ; reinterpret_cast<char*>(symbol) < p_data.data() +
                p_data.size(); ++symbol)
            {
                if (ELF64_ST_TYPE(symbol->st_info) == STT_FUNC &&
                    ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL &&
                    symbol->st_value == 0)
                {
                    name_offsets.push_back(symbol->st_name);
                    symbols.push_back(symbol);
                }
            }

            // mix the symbols
            srand(time(NULL));
            for (std::vector<Elf64_Sym*>::iterator it = symbols.begin();
                 it != symbols.end(); ++it)
            {
                int index = rand() % name_offsets.size();
                (*it)->st_name = name_offsets[index];
                name_offsets.erase(name_offsets.begin() + index);
            }

            return true;
        }
    }

    std::cerr << "Never found the dynamic symbol table" << std::endl;
    return false;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./mixDynamicSymbols <file path>" << std::endl;
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

    if (!append_dynsym(input))
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
