#include "instruction_container.hpp"
#include "wild_context.hpp"

#include <idp.hpp>

#include <algorithm>

bool instruction_container::decode_assembly(ud_instruction& instruction)
{
	int err = 0;

	if ((err = ud_disassemble(&instruction)) != 0)
	{
		this->push_back(instruction);
		return true;
	}
	else
	{
		msg("Decode err: %d. PC is %08x\n", err,
			instruction.pc);
	}
	
	return false;
}

void instruction_container::print_assembly(FILE* file)
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		ud_instruction& instruction = this->at(i);
		
		instruction.translator(&instruction);

		if (file)
			fprintf(file, "%016llx %s\n", instruction.get_address(), ud_insn_asm(&instruction));
		else
			msg("%016llx %s\n", instruction.get_address(), ud_insn_asm(&instruction));
	}
}

void instruction_container::print_syntax(wild_context& context, ud_instruction& instruction, uint32_t handler_offset, FILE* file)
{
	instruction.translator(&instruction);

	if (file)
		fprintf(file, "{%04X} [%08X-%08X-%08X-%08X-%08X] %s\n", handler_offset, context.step_params[0], context.step_params[1], context.step_params[2], context.step_params[3], context.step_params[4], ud_insn_asm(&instruction));
	else
		msg("%08X {%04X} [%08X-%08X-%08X-%08X-%08X] %s\n", instruction.get_address<uint32_t>(), 
		handler_offset, context.step_params[0], context.step_params[1], context.step_params[2], context.step_params[3], context.step_params[4], ud_insn_asm(&instruction));
}

void instruction_container::update_indexes()
{
	for (std::size_t i = 0; i < this->size(); i++)
		this->at(i).set_index(i);
}

bool instruction_container::has_address(uint32_t address) const
{
	instruction_container_base::size_type index = 0;
	instruction_container_base::const_iterator iter;

	return this->find(iter, index, [address](value_type const& value) -> bool
	{
		return (value.is_address<uint32_t>(address));
	});
}

bool instruction_container::find_address_index(uint32_t address, instruction_container_base::size_type& index) const
{
	return this->find_index(index, [address](value_type const& value) -> bool
	{
		return (value.is_address<uint32_t>(address));
	});
}

bool instruction_container::find_mnemonic_index(ud_mnemonic_code mnemonic, instruction_container_base::size_type& index) const
{
	return this->find_index(index, [mnemonic](value_type const& value) -> bool
	{
		return value.is_mnemonic(mnemonic);
	});
}

bool instruction_container::find_index_by_register_base(ud_type base, std::size_t& index, ud_instruction& instruction)
{
	return this->find_index(index, [&, base](ud_instruction const& value) -> bool
	{
		if (value.is_operand_type(0, UD_OP_REG) &&
			value.is_operand_base(0, base))
		{
			instruction = value;
			return true;
		}

		return false;
	});
}

bool instruction_container::find_index_by_memory_base(ud_type base, std::size_t operand, std::size_t& index, ud_instruction& instruction)
{
	return this->find_index(index, [&, base, operand](value_type const& value) -> bool
	{
		if (value.is_operand_type(operand, UD_OP_MEM) &&
			value.is_operand_base(operand, base))
		{
			instruction = value;
			return true;
		}

		return false;
	});
}

bool instruction_container::find_index(instruction_container_base::size_type& index, instruction_container_base::predicate_function predicate) const
{
	instruction_container_base::const_iterator iter;
	
	if (this->find(iter, index, predicate))
	{
		index = (iter - this->cbegin());
		return true;
	}

	return false;
}

bool instruction_container::find(instruction_container_base::const_iterator& iter, instruction_container_base::size_type& index, instruction_container_base::predicate_function predicate) const
{
	if (index >= this->size())
		return false;

	return ((iter = std::find_if(this->cbegin() + index, this->cend(), predicate)) != this->cend());
}