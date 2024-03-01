#include "wild_handler_flow.hpp"

wild_handler_flow::wild_handler_flow()
{
	memset(this, 0, sizeof(wild_handler_flow));
}

bool wild_handler_flow::decrypt_flow_data(instruction_container& instructions, wild_context& context)
{
	if (instructions.back().is_mnemonic(UD_Ijmp))
	{
		std::size_t index = 0;

		if (!this->find_read_index(instructions, context, index))
			return false;

		ud_type base = instructions.at(index).get_base_type(0);

		if (!this->find_read_offset(instructions, base, index))
			return false;

		ud_instruction& delta_instruction = instructions.at(instructions.size() - 2);

		if (delta_instruction.is_mnemonic(UD_Iadd))
			return this->find_add_data_index(instructions, context, base, index);
		else if (delta_instruction.is_mnemonic(UD_Isub))
			return this->find_sub_data_index(instructions, base, index);
	}

	return true;
}

bool wild_handler_flow::find_read_index(instruction_container& instructions, wild_context& context, std::size_t& index)
{
	for (std::size_t i = (instructions.size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/* 0: mov reg,[ebp+xx]*/
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			context.is_opcode_access_instruction(instructions.at(i)))
		{
			this->flow_read_index = (index = i);
			return true;
		}
	}

	return false;
}

bool wild_handler_flow::find_read_offset(instruction_container& instructions, ud_type base, std::size_t& index)
{
	for (index++; index < instructions.size(); index++)
	{
		/* 0: add reg,imm */
		if (instructions.at(index).is_mnemonic(UD_Iadd) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_base(0, base) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM))
		{
			this->flow_read_offset = instructions.at(index).get_operand_data<uint16_t>(1);
			return true;
		}
	}

	return false;
}

bool wild_handler_flow::find_add_data_index(instruction_container& instructions, wild_context& context, ud_type base, std::size_t& index)
{
	for (index++; index < instructions.size(); index++)
	{
		/* 0: movzx reg,word ptr [reg] */
		if (instructions.at(index).is_mnemonic(UD_Imovzx) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_type(1, UD_OP_MEM, UD_SIZE_WORD) &&
			instructions.at(index).is_operand_base(1, base) &&
			instructions.at(index).has_operand_index_not(1) &&
			instructions.at(index).has_operand_scale_not(1) &&
			instructions.at(index).has_operand_data_not(1))
		{
			this->flow_data_index = index;
			return this->find_add_and(instructions, context, instructions.at(index).get_base_type(0), index);
		}
		/* 0: mov reg,word ptr [reg] */
		else if (instructions.at(index).is_mnemonic(UD_Imov) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_type(1, UD_OP_MEM, UD_SIZE_WORD) &&
			instructions.at(index).is_operand_base(1, base) &&
			instructions.at(index).has_operand_index_not(1) &&
			instructions.at(index).has_operand_scale_not(1) &&
			instructions.at(index).has_operand_data_not(1))
		{
			this->flow_data_index = index;
			return true;
		}
	}

	return false;
}

bool wild_handler_flow::find_add_and(instruction_container& instructions, wild_context& context, ud_type base, std::size_t& index)
{
	for (index++; index < instructions.size(); index++)
	{
		/* 0: and reg,0xffff */
		if (instructions.at(index).is_mnemonic(UD_Iand) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_base(0, base) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index).is_operand_data(1, 0xFFFF))
		{
			return true;
		}

		if (instructions.at(index).compare_mnemonic(false, false, true))
		{
			if (context.is_key_access_instruction(instructions.at(index), false))
			{
				/* 0: ___ reg,[ebp+xx] */
				if (instructions.at(index).is_operand_type(0, UD_OP_REG) &&
					instructions.at(index).is_operand_base(0, base))
				{
					this->flow_key_indexes.push_back(index);
				}
				/* 0: ___ [ebp+xx],reg */
				else if (instructions.at(index).is_operand_type(1, UD_OP_REG) &&
					instructions.at(index).is_operand_base(1, base))
				{
					this->flow_key_indexes.push_back(index);
				}
			}
			/* 0: ___ reg,imm  */
			else if (instructions.at(index).is_operand_type(0, UD_OP_REG) &&
				instructions.at(index).is_operand_base(0, base) &&
				instructions.at(index).is_operand_type(1, UD_OP_IMM))
			{
				this->flow_mutation_index = index;
				this->flow_mutation_mnemonic = instructions.at(index).get_mnemonic();
				this->flow_mutation_constant = instructions.at(index).get_operand_data(1);
			}
		}
	}

	return false;
}

bool wild_handler_flow::find_sub_data_index(instruction_container& instructions, ud_type base, std::size_t& index)
{
	for (index++; index < instructions.size(); index++)
	{
		/* 0: mov reg,dword ptr [reg] */
		if (instructions.at(index).is_mnemonic(UD_Imov) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(index).is_operand_base(1, base) &&
			instructions.at(index).has_operand_index_not(1) &&
			instructions.at(index).has_operand_scale_not(1) &&
			instructions.at(index).has_operand_data_not(1))
		{
			this->flow_data_index = index;
			return this->find_sub_negative_check(instructions, instructions.at(index).get_base_type(0), index);
		}
	}

	return false;
}
	
bool wild_handler_flow::find_sub_negative_check(instruction_container& instructions, ud_type base, std::size_t& index)
{
	for (index++; index < instructions.size(); index++)
	{
		/* 0: and reg,0x80000000 */
		if (instructions.at(index).is_mnemonic(UD_Iand) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_base(0, base) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index).is_operand_data(1, 0x80000000))
		{
			return true;
		}
	}

	return false;
}