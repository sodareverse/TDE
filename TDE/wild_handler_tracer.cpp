#include "wild_handler_tracer.hpp"

#include <idp.hpp>

#define OBFUSCATION_BRANCH_COUNT	15

wild_handler_tracer::wild_handler_tracer(wild_context& context)
	: context(context)
{

}

void wild_handler_tracer::trace(uint32_t vm_handler, uint32_t& compares, instruction_container& instructions)
{
	this->tracing_branch_obfuscation = false;

	this->branch_continue = 0;
	this->branch_remaining = 0;

	this->jcc_branches.clear();

	ud_instruction instruction(vm_handler);
	instruction.set_input(this->context.to_segment(vm_handler));

	while (instructions.decode_assembly(instruction))
	{
		if (instruction.is_mnemonic(UD_Icmp))
			this->trace_cmp(compares);
		else if (instruction.is_mnemonic(UD_Ijmp))
		{
			if (!this->trace_jmp(instructions, instruction))
				break;
		}
		else if (instruction.is_mnemonic(UD_Iret))
		{
			if (!this->trace_ret(instructions, instruction))
				break;
		}
		else if (instruction.is_mnemonic_jcc())
		{
			if (!this->trace_jcc(instructions, instruction, compares))
				break;
		}
	}
}

void wild_handler_tracer::trace_cmp(uint32_t& compares)
{
	compares++;
}

bool wild_handler_tracer::trace_jmp(instruction_container& instructions, ud_instruction& instruction)
{
	if (instruction.is_operand_type(0, UD_OP_JIMM))
	{
		if (instructions.has_address(instruction.get_address_next<uint32_t>()))
			return this->trace_jcc_back(instructions, instruction);
		
		instructions.pop_back();
		instruction.skip_input(instruction.get_operand_data<uint32_t>(0));
	}
	else
	{
		return this->trace_branch_obfuscation_continue(instruction);
	}

	return true;
}

bool wild_handler_tracer::trace_ret(instruction_container& instructions, ud_instruction& instruction)
{
	return this->trace_branch_obfuscation_continue(instruction);
}

bool wild_handler_tracer::trace_jcc(instruction_container& instructions, ud_instruction& instruction, uint32_t& compares)
{
	if (instructions.try_evaluate_branch_simple())
	{
		if (compares == 3)
			this->trace_branch_compares(instructions);

		if (this->tracing_branch_obfuscation)
			this->trace_branch_obfuscation(instruction);
		else
			this->jcc_branches.push(instruction.get_address_next<uint32_t>());
	}
	else if (instructions.try_evaluate_branch(instruction))
	{
		instructions.pop_back();
		instruction.skip_input(instruction.get_operand_data<uint32_t>(0));
	}
	
	return (!instructions.has_address(instruction.get_address_next<uint32_t>()));
}

void wild_handler_tracer::trace_branch_compares(instruction_container& instructions)
{
	if (this->is_branch_obfuscation(instructions))
	{
		this->tracing_branch_obfuscation = true;
		this->branch_remaining = OBFUSCATION_BRANCH_COUNT;
	}
	else
	{
		this->tracing_branch_obfuscation = false;
	}
}

void wild_handler_tracer::trace_branch_obfuscation(ud_instruction& instruction)
{
	if (this->branch_remaining > 0)
		instruction.skip_input(instruction.get_operand_data<uint32_t>(0));
	else if (this->branch_remaining == 0)
		this->branch_continue = instruction.get_address_next<uint32_t>();

	this->branch_remaining--;
}

bool wild_handler_tracer::trace_branch_obfuscation_continue(ud_instruction& instruction)
{
	if (this->tracing_branch_obfuscation && this->branch_continue)
	{
		instruction.reset_input(this->branch_continue);

		this->tracing_branch_obfuscation = false;
		this->branch_continue = 0;
		return true;
	}

	return false;
}

bool wild_handler_tracer::trace_jcc_back(instruction_container& instructions, ud_instruction& instruction)
{
	if (!this->jcc_branches.empty())
	{
		while (!this->jcc_branches.empty())
		{
			uint32_t jcc_destination = this->jcc_branches.top();

			this->jcc_branches.pop();

			if (!instructions.has_address(jcc_destination))
			{
				uint32_t base_address = static_cast<uint32_t>(instruction.pc - instruction.inp_buf_index);
				uint32_t base_offset = (jcc_destination - base_address);

				instruction.reset_input(jcc_destination);
				return true;
			}
		}
	}

	return false;
}

bool wild_handler_tracer::is_branch_obfuscation(instruction_container& instructions)
{
	if (instructions.size() > 6)
	{
		std::size_t index = (instructions.size() - 6);

		/*
			0: cmp reg,imm
			1: je ____
			2: cmp reg,imm
			3: je ____
			4: cmp reg,imm
			5: jne ___
		*/
		return (instructions.at(index).is_mnemonic(UD_Icmp) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			
			instructions.at(index + 1).is_mnemonic(UD_Ijz) &&

			instructions.at(index + 2).is_mnemonic(UD_Icmp) &&
			instructions.at(index + 2).is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE) &&
			instructions.at(index + 2).is_operand_base(0, instructions.at(index), 0) &&
			instructions.at(index + 2).is_operand_type(1, UD_OP_IMM) &&
			
			instructions.at(index + 3).is_mnemonic(UD_Ijz) &&

			instructions.at(index + 4).is_mnemonic(UD_Icmp) &&
			instructions.at(index + 4).is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE) &&
			instructions.at(index + 4).is_operand_base(0, instructions.at(index + 2), 0) &&
			instructions.at(index + 4).is_operand_type(1, UD_OP_IMM) &&
			
			instructions.at(index + 5).is_mnemonic(UD_Ijnz));
	}

	return false;
}