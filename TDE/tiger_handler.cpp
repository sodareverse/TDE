#include "tiger_handler.hpp"
#include "tiger_handler_types.hpp"

#include "instruction_emulator.hpp"

#include <idp.hpp>

/*
Imagebase:		00400000
Context:		0041D3AF
Imagebase o:	00000027
PImagebase o:	00000047
PImagebase:		00400000
Opcode o:		0000008F
HTable:			004A8CED
HTable o:		0000000B
HTable count:	0000033A

0000000000445330 mov dword [ebp+0x7a], 0x0
000000000044533e mov dword [ebp+0xf], 0x0
000000000044534c mov dword [ebp+0x21], 0x0
000000000044535a mov dword [ebp+0x83], 0x0
0000000000445368 mov dword [ebp+0x6d], 0x0
0000000000445376 mov word [ebp+0x32], 0x0
0000000000445382 mov word [ebp+0x2f], 0x0
000000000044538f mov word [ebp+0x38], 0x0
000000000044539c mov dword [ebp+0x1d], 0x0
00000000004453aa mov dword [ebp+0x17], 0x0
*/

tiger_handler::tiger_handler(uint16_t index)
	: wild_handler(index)
{
	for (uint32_t i = 0; i < _countof(this->operands); i++)
	{
		this->operands[i].type = UD_NONE;
		this->operands[i].size = UD_SIZE_NONE;
		this->operands[i].index = static_cast<std::size_t>(-1);
	}
}

bool tiger_handler::update_argument_data(tiger_context& context)
{
	if (this->id != WILD_HANDLER_INVALID)
	{
		
	}

	return true;
}

bool tiger_handler::map_handler_specific(instruction_container& instructions, wild_context& context)
{
	try
	{
		return this->map_handler_tiger(instructions, dynamic_cast<tiger_context&>(context));
	}
	catch (std::bad_cast const& e)
	{
		msg("[CodeDevirtualizer] Exception: %s\n", e.what());
	}

	return false;
}

bool tiger_handler::map_handler_tiger(instruction_container& instructions, tiger_context& context)
{
	if (this->map_handler_call(instructions, context) ||
		this->map_handler_nop(instructions, context) ||
		this->map_handler_push(instructions, context) ||
		this->map_handler_pop(instructions, context) ||
		this->map_handler_inc(instructions, context) ||
		this->map_handler_dec(instructions, context) ||
		this->map_handler_not(instructions, context) ||
		this->map_handler_neg(instructions, context) ||
		this->map_handler_mov(instructions, context) ||
		this->map_handler_movsx(instructions, context) ||
		this->map_handler_movzx(instructions, context) ||
		this->map_handler_add(instructions, context) ||
		this->map_handler_sub(instructions, context) ||
		this->map_handler_and(instructions, context) ||
		this->map_handler_xor(instructions, context) ||
		this->map_handler_or(instructions, context) ||
		this->map_handler_shl(instructions, context) ||
		this->map_handler_shr(instructions, context) ||
		this->map_handler_rcl(instructions, context) ||
		this->map_handler_rcr(instructions, context) ||
		this->map_handler_rol(instructions, context) ||
		this->map_handler_ror(instructions, context) ||
		this->map_handler_cmp(instructions, context) ||
		this->map_handler_test(instructions, context) ||
		this->map_handler_imul(instructions, context))
	{
		if (this->decrypt_tiger_data(instructions, context))
			return true;
	}
	
	//msg("[CodeDevirtualizer] Failed to either map- or decrypt handler data for handler %04X (%04X) of type tiger.\n", this->index, this->id);
	return true;
}

bool tiger_handler::map_handler_call(instruction_container& instructions, tiger_context& context)
{
	if (instructions.back().is_mnemonic(UD_Iret))
	{
		this->operands[0].type = UD_NONE;

		if (instructions.bounds(3) &&
			instructions.at(2).is_operand_size(1, UD_SIZE_DWORD) &&
			instructions.at(3).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(3).is_operand_base(1, UD_R_EBP) &&
			instructions.at(3).is_operand_data(1, context.vm_imagebase_offset))
		{
			this->operands[0].type = UD_OP_IMM;
		}
		else if (instructions.bounds(4) &&
			instructions.at(4).is_mnemonic(UD_Imov) &&
			instructions.at(4).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD))
		{
			if (instructions.bounds(5) &&
				instructions.at(5).is_mnemonic(UD_Imov) &&
				instructions.at(5).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
				instructions.at(5).is_operand_base(1, instructions.at(4), 0))
			{
				this->operands[0].type = UD_OP_MEM;
			}
			else
			{
				this->operands[0].type = UD_OP_REG;
			}
		}

		this->id = WILD_HANDLER_CALL;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_nop(instruction_container& instructions, tiger_context& context)
{
	if (this->flow_read_index == 0)
	{
		this->id = TIGER_HANDLER_NOP;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_push(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Ipush))
	{
		if (instructions.bounds(index, 1) &&
			instructions.at(index + 1).is_mnemonic_not({ UD_Ipopfw, UD_Ipopfd, UD_Ipopfq }))
		{
			this->id = TIGER_HANDLER_PUSH;
			return true;
		}
	}

	return false;
}

bool tiger_handler::map_handler_pop(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Ipop))
	{
		this->id = TIGER_HANDLER_POP;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_inc(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Iinc))
	{
		/* Maybe consider that 'no flags' is actually "lea reg,[reg+x]" */
		this->id = TIGER_HANDLER_INC;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_dec(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Idec))
	{
		this->id = TIGER_HANDLER_DEC;
		return true;
	}

	return false;
}
	
bool tiger_handler::map_handler_not(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Inot))
	{
		this->id = TIGER_HANDLER_NOT;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_neg(instruction_container& instructions, tiger_context& context)
{
	std::size_t index = 0;

	if (this->map_unary_operation(instructions, context, index, UD_Ineg))
	{
		this->id = TIGER_HANDLER_NEG;
		return true;
	}

	return false;
}

bool tiger_handler::map_handler_mov(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_movsx(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_movzx(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_add(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_sub(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_and(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_xor(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_or(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_shl(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_shr(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_rcl(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_rcr(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_rol(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_ror(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_cmp(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_test(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_handler_imul(instruction_container& instructions, tiger_context& context)
{
	return false;
}

bool tiger_handler::map_unary_operation(instruction_container& instructions, tiger_context& context, std::size_t& index, ud_mnemonic_code mnemonic)
{
	ud_instruction operand_key_instruction;
	
	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		if (this->find_operand_key_read_instruction(instructions, context, TIGER_KEY_OPERAND_0, i, operand_key_instruction))
		{
			ud_type operand_type = UD_OP_REG;

			for (std::size_t j = i + 1, stage = 0; j < instructions.size(); j++)
			{
				if (stage == 0 && 
					instructions.at(j).is_mnemonic(UD_Iadd) &&
					instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, operand_key_instruction, 0) &&
					instructions.at(j).is_operand_type(1, UD_OP_REG) &&
					instructions.at(j).is_operand_base(1, UD_R_EBP))
				{
					stage++;
				}
				else if (stage == 1)
				{
					if (instructions.at(j).is_mnemonic(UD_Imov) &&
						instructions.at(j).is_operand_type(0, UD_OP_REG) &&
						instructions.at(j).is_operand_base(0, operand_key_instruction, 0))
					{
						if (instructions.at(j).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
							instructions.at(j).is_operand_base(1, operand_key_instruction, 0))
						{
							operand_type = UD_OP_MEM;
						}
						else
						{
							break;
						}
					}
					else if (instructions.at(j).is_mnemonic(mnemonic) &&
						instructions.at(j).is_operand_type(0, UD_OP_MEM) &&
						instructions.at(j).is_operand_base(0, operand_key_instruction, 0))
					{
						this->operands[0].type = operand_type;
						this->operands[0].size = instructions.at(j).get_operand_size(0);
						this->operands[0].index = i;

						index = j;
						return true;
					}
				}
			}
		}
	}

	return false;
}

bool tiger_handler::decrypt_tiger_data(instruction_container& instructions, tiger_context& context)
{
	return (this->decrypt_tiger_operand_data(instructions, context, TIGER_KEY_OPERAND_0, this->operands[0].key_decoders) &&
		this->decrypt_tiger_operand_data(instructions, context, TIGER_KEY_OPERAND_1, this->operands[1].key_decoders));
}
	
bool tiger_handler::decrypt_tiger_operand_data(instruction_container& instructions, tiger_context& context, uint8_t operand_key, std::vector<tiger_operand_decoder>& key_decoders)
{
	std::size_t index = 0;
	ud_instruction operand_key_instruction;
	
	if (this->find_operand_key_read_instruction(instructions, context, operand_key, index, operand_key_instruction))
	{
		/* 0: ___ reg,imm */
		while (instructions.bounds(++index) &&
			instructions.at(index).compare_mnemonic(false, false, true) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_base_family(0, operand_key_instruction, 0) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM))
		{
			key_decoders.push_back({ instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_size(1), instructions.at(index).get_operand_data(1) });
		}
	}

	return true;
}

bool tiger_handler::find_operand_key_read_instruction(instruction_container& instructions, tiger_context& context, uint8_t operand_key, std::size_t& index, ud_instruction& instruction)
{
	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/* 0: mov reg,word ptr [ebp+xx] */
		if (instructions.at(i).is_mnemonic(UD_Imovzx) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_WORD) &&
			instructions.at(i).is_operand_base(1, UD_R_EBP) &&
			instructions.at(i).has_operand_index_not(1) &&
			instructions.at(i).has_operand_scale_not(1) &&
			instructions.at(i).is_operand_data(1, context.get_key_offset(operand_key)))
		{
			index = i;
			instruction = instructions.at(i);
			return true;
		}
	}

	return false;
}

bool tiger_handler::step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	try
	{
		return this->step_handler_tiger(instructions, dynamic_cast<tiger_context&>(context), opcode);
	}
	catch (std::bad_cast const& e)
	{
		msg("[CodeDevirtualizer] Exception: %s\n", e.what());
	}

	return false;
}

bool tiger_handler::step_handler_tiger(instruction_container& instructions, tiger_context& context, opcode_reader& opcode)
{
	switch (this->id)
	{
	case TIGER_HANDLER_NOP:
		return this->step_handler_nop(instructions, context, opcode);

	case TIGER_HANDLER_PUSH:
		return this->step_handler_push(instructions, context, opcode);

	case TIGER_HANDLER_POP:
		return this->step_handler_pop(instructions, context, opcode);

	default:
		this->step_opcode_regions(context, opcode);
		return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
		break;
	}

	return false;
}

bool tiger_handler::step_handler_nop(instruction_container& instructions, tiger_context& context, opcode_reader& opcode)
{
	context.step_params[0] = UD_Inop;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Inop);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(0), true);
}

bool tiger_handler::step_handler_push(instruction_container& instructions, tiger_context& context, opcode_reader& opcode)
{
	this->step_opcode_regions(context, opcode);

	uint32_t register_id = context.get_key_data(TIGER_KEY_OPERAND_0);

	for (std::size_t i = 0; i < this->operands[0].key_decoders.size(); i++)
		instruction::emulate(this->operands[0].key_decoders.at(i).mnemonic, this->operands[0].key_decoders.at(i).size, this->operands[0].key_decoders.at(i).data, &register_id);

	context.step_params[0] = register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ipush);
	instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
	instruction.set_operand_base(0, context.get_vm_register(register_id));

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool tiger_handler::step_handler_pop(instruction_container& instructions, tiger_context& context, opcode_reader& opcode)
{
	this->step_opcode_regions(context, opcode);

	uint32_t register_id = context.get_key_data(TIGER_KEY_OPERAND_0);
	
	for (std::size_t i = 0; i < this->operands[0].key_decoders.size(); i++)
		instruction::emulate(this->operands[0].key_decoders.at(i).mnemonic, this->operands[0].key_decoders.at(i).size, this->operands[0].key_decoders.at(i).data, &register_id);

	context.step_params[0] = register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ipop);
	instruction.set_operand_type(0, this->operands[0].type, this->operands[0].size);

	if (context.current_register_type < 0)
	{
		if (this->operands[0].type == UD_OP_REG) 
			instruction.set_operand_base(0, context.get_vm_register(register_id), this->operands[0].size);
		else /* if (this->operands[0].type == UD_OP_MEM) */
			instruction.set_operand_base(0, context.get_vm_register(register_id));
	}
	else
	{
		ud_type base = static_cast<ud_type>(UD_R_EAX + context.current_register_type--);

		if (base != UD_R_ESP)
			context.set_vm_register(register_id, base);
		
		instruction.set_operand_base(0, base);
	}
	
	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}