#include "tiger.hpp"

#include <idp.hpp>

tiger::tiger()
	: wild(this->context)
{

}

bool tiger::is_signature(instruction_container& vm_entrance)
{
	msg("[CodeDevirtualizer] TIGER machine identified.\n");
	return true;
}

bool tiger::parse_initial_handler(instruction_container& instructions)
{
	static const ud_size operand_sizes[] = 
	{
		UD_SIZE_DWORD,	UD_SIZE_DWORD,	UD_SIZE_DWORD,	UD_SIZE_DWORD,
		UD_SIZE_DWORD,	UD_SIZE_WORD,	UD_SIZE_WORD,	UD_SIZE_WORD,
		UD_SIZE_DWORD,	UD_SIZE_DWORD
	};
	
	if (instructions.size() < _countof(operand_sizes))
		return false;

	for (std::size_t i = 0; i < _countof(operand_sizes); i++)
	{
		/* 0: mov [ebp+xx],0x00 */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_MEM, operand_sizes[i]) &&
			instructions.at(i).is_operand_base(0, UD_R_EBP) &&
			instructions.at(i).has_operand_index_not(0) &&
			instructions.at(i).has_operand_scale_not(0) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(i).is_operand_data(1, 0))
		{
			this->context.add_key(instructions.at(i).get_operand_data(0));
		}
		else
		{
			return false;
		}
	}
	
	return true;
}

bool tiger::update_argument_data()
{
	return true;

	if (!this->context.tiger_operands[0].is_found ||
		!this->context.tiger_operands[1].is_found)
	{
		return false;
	}
	
	for (std::size_t i = 0; i < this->handlers.size(); i++)
	{
		if (!this->handlers.at(i).update_argument_data(this->context))
			return false;
	}

	return true;
}