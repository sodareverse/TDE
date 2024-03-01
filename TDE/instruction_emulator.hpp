#ifndef INSTRUCTION_EMULATOR_HPP_
#define INSTRUCTION_EMULATOR_HPP_

#include "ud_instruction.hpp"

namespace instruction
{
	bool emulate(ud_mnemonic_code mnemonic, ud_size size, uint32_t input, uint32_t* product);
	bool emulate_eflags(ud_mnemonic_code mnemonic, ud_size size, uint32_t input, uint32_t product, uint32_t* eflags);
};

#endif