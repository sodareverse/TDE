#include "wild_base.hpp"

#include "instruction_emulator.hpp"

#include <idp.hpp>
#include <allins.hpp>

wild_base::wild_base(wild_context& context)
	: wild_handler_parser(context)
{

}

bool wild_base::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions)
{
	if (!decode_insn(vm_function) || (cmd.itype != NN_jmp && cmd.itype != NN_call))
	{
		msg("[CodeDevirtualizer] Instruction at %08X either could not be decoded or is not a jump or call.\n", vm_function);
		return false;
	}
	
	context.set_initial_parameters(vm_instructions.at(0).get_operand_data(0), vm_instructions.at(1).get_operand_data(0));
	
	if (!decode_insn(vm_instructions.at(2).get_address<uint32_t>()))
	{
		msg("[CodeDevirtualizer] Instruction at %08X could not be decoded.\n", vm_instructions.at(2).get_address<uint32_t>());
		return false;
	}
	
	this->vm_function = vm_function;

	if (this->vm_entrance != cmd.Operands[0].addr)
	{
		if (!this->parse_virtual_machine(cmd.Operands[0].addr))
			return false;
	}
	
	context.prepare_initial_parameters();

	vm_instructions.clear();

	if (!this->trace_function(vm_instructions))
	{
		msg("[CodeDevirtualizer] Could not trace selected function.\n");
		return false;
	}

	this->process_virtual_function(vm_instructions);
	return true;
}

bool wild_base::parse_virtual_machine(uint32_t vm_entrance)
{
	this->context.clear();

	if (!this->context.make_segment_copy(vm_entrance))
	{
		msg("[CodeDevirtualizer] Could not create segment copy.\n");
		return false;
	}
				
	if (!this->context.decode_zero_data(vm_entrance))
	{
		msg("[CodeDevirtualizer] Could not decode zero data.\n");
		return false;
	}

	msg("VM vars:\n");
	msg("Imagebase:\t%08X\n", this->context.vm_imagebase);
	msg("Context:\t\t%08X\n", this->context.vm_context);
	msg("Imagebase o:\t%08X\n", this->context.vm_imagebase_offset);
	msg("PImagebase o:\t%08X\n", this->context.vm_imagebase_preferred_offset);
	msg("PImagebase:\t%08X\n", this->context.vm_imagebase_preferred);
	msg("Opcode o:\t\t%08X\n", this->context.vm_opcode_offset);
	msg("HTable:\t\t%08X\n", this->context.vm_handler_table);
	msg("HTable o:\t\t%08X\n", this->context.vm_handler_table_offset);
	msg("HTable count:\t%08X\n", this->context.vm_handler_count);

	if (!this->parse_initial_handlers())
	{
		msg("[CodeDevirtualizer] Could not parse the correct keys.\n");
		return false;
	}

	if (!this->parse_virtual_handlers())
	{
		msg("[CodeDevirtualizer] Could not parse virtual handlers.\n");
		return false;
	}
		
	if (!this->update_argument_data())
	{
		msg("[CodeDevirtualizer] Failed to update argument data.\n");
		return false;
	}

	this->vm_entrance = vm_entrance;
	return true;
}

bool wild_base::trace_function(instruction_container& instructions)
{
	this->context.reset_labels();
	this->context.create_label(this->context.initial_virtual_opcode, this->context.initial_handler_offset);
	this->context.current_register_type = (UD_R_EDI - UD_R_EAX);

	std::vector<wild_opcode_label>::iterator iter;

	while (this->context.find_label_unread(iter))
	{
		iter->is_read = true;
		msg("[CodeDevirtualizer] Reading virtual opcode label at %08X\n", iter->address);
		
		if (!instructions.has_address(iter->address))
		{
			this->context.current_virtual_opcode = iter->address;
			this->context.current_handler_offset = iter->offset;
			
			iter->offset = 0;

			if (!this->process_virtual_pointer(instructions, *iter))
			{
				printf("Failed to process virtual pointer.\n");
				return false;
			}
		}
	}

	return true;
}

bool wild_base::process_virtual_pointer(instruction_container& instructions, wild_opcode_label& label)
{
	label.offset = this->context.current_virtual_opcode;
	
	wild_handler* handler = nullptr;

	do
	{
		uint16_t handler_offset = static_cast<uint16_t>(this->context.current_handler_offset);

		if (!this->fetch_virtual_handler(handler_offset, &handler) || handler == nullptr)
		{
			msg("[CodeDevirtualizer] Handler out of bounds (%04X): %08X, Key: %04X.\n", handler_offset, this->context.current_virtual_opcode, this->context.current_handler_offset);
			return false;
		}

		uint8_t* virtual_opcode_address = this->context.to_segment(this->context.current_virtual_opcode).first;

		if (!virtual_opcode_address)
		{
			msg("[CodeDevirtualizer] Virtual opcode segment not found.\n");
			return false;
		}
		
		if (instructions.has_address(this->context.current_virtual_opcode))
			break;

		opcode_reader opcode(virtual_opcode_address);
		
		if (!handler->step_handler(instructions, this->context, opcode))
		{
			msg("[CodeDevirtualizer] Virtual pointer step failed with handler id %04X: %08X, Key: %04X.\n", handler->get_id(), this->context.current_virtual_opcode, this->context.current_handler_offset);
			return false;
		}
		
		instructions.print_syntax(this->context, instructions.back(), handler_offset);
		label.offset = std::max(this->context.current_virtual_opcode, label.offset);
	}
	while (!handler->is_flow_type());

	return true;
}

void wild_base::process_virtual_function(instruction_container& instructions)
{
	//std::sort(instructions.begin(), instructions.end());

	//this->deobfuscate_prologue(instructions);
	//this->deobfuscate_epilogue(instructions);
	//
	//this->deobfuscate_fish_addr_register(instructions);
	//this->deobfuscate_repeat_prefix(instructions);

	//for (std::size_t i = 0; i < instructions.size(); i++)
	//{
	//	if (instructions.at(i).mnemonic == FISH_MNEMONIC_CRYPT)
	//		instructions.at(i).mnemonic = MNEMONIC_MOV;
	//}

	//FILE* f = fopen("C:\\DEVIRTUALIZER\\fish_uv.txt", "w");

	//for (std::size_t i = 0; i < instructions.size(); i++)
	//	this->print_fish_assembly(f, instructions.at(i), 0xFFFF);

	//fclose(f);
}

bool wild_base::parse_initial_handlers()
{
	static const uint32_t max_key_attempts = 5;

	for (uint32_t i = 0, compares = 0; i < max_key_attempts; i++)
	{
		this->context.reset_keys();

		if (this->context.current_handler_offset < this->context.vm_handler_count)
		{
			instruction_container handler_instructions;
			this->decode_virtual_handler(handler_instructions, this->context.current_handler_offset, compares);

#ifdef CREATE_VM_DUMPS
			//handler_instructions.print_assembly();
#endif

			if (this->parse_initial_handler(handler_instructions))
				return true;

			if (!this->parse_next_handler_offset(handler_instructions))
				return false;
		}
	}

	return false;
}

bool wild_base::parse_virtual_handlers()
{
#ifdef CREATE_VM_DUMPS
	FILE* f = fopen("C:\\DEVIRTUALIZER\\fish_vm_raw.txt", "w");
#endif
	
	for (uint32_t i = 0, compares = 0; i < this->context.vm_handler_count; i++)
	{
		instruction_container handler_instructions;
		this->decode_virtual_handler(handler_instructions, i, compares);

		if (!this->parse_virtual_handler(handler_instructions, i, compares))
			return false;

#ifdef CREATE_VM_DUMPS
		fprintf(f,"//////////////////////////////////////////////\r\n// FISH Virtual Handler %04X 00000000\r\n\n", i);
		handler_instructions.print_assembly(f);
#endif
	}
	
#ifdef CREATE_VM_DUMPS
	fclose(f);
#endif

	return true;
}

bool wild_base::parse_next_handler_offset(instruction_container& instructions)
{
	if (instructions.size() >= 3)
	{
		std::size_t index = (instructions.size() - 2);
		
		/*
			0: add dword ptr [ebp+xx],imm
			1: jmp reg
		*/
		if (instructions.at(index).is_mnemonic(UD_Iadd) &&
			instructions.at(index).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(index).is_operand_base(0, UD_R_EBP) &&
			instructions.at(index).has_operand_index_not(0) &&
			instructions.at(index).has_operand_scale_not(0) &&
			instructions.at(index).is_operand_data(0, this->context.vm_opcode_offset) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index + 1).is_mnemonic(UD_Ijmp))
		{
			uint32_t vm_opcode_delta = instructions.at(index).get_operand_data(1);

			for (std::size_t i = index; static_cast<int32_t>(i) >= 0; i--)
			{
				/* 0: mov reg,dword ptr [ebp+xx] */
				if (instructions.at(i).is_mnemonic(UD_Imov) &&
					instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
					instructions.at(i).is_operand_base_not(0, UD_R_ESP) &&
					instructions.at(i).is_operand_base_not(0, UD_R_EBP) &&
					instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
					instructions.at(i).is_operand_base(1, UD_R_EBP) &&
					instructions.at(i).has_operand_index_not(1) &&
					instructions.at(i).has_operand_scale_not(1) &&
					instructions.at(i).is_operand_data(1, this->context.vm_opcode_offset))
				{
					/* 1: add reg,imm */
					if (instructions.at(i + 1).is_mnemonic(UD_Iadd) &&
						instructions.at(i + 1).is_operand_type(0, UD_OP_REG) &&
						instructions.at(i + 1).is_operand_base(0, instructions.at(i), 0) &&
						instructions.at(i + 1).is_operand_type(1, UD_OP_IMM) &&
						vm_opcode_delta < 32)
					{
						opcode_reader opcode(this->context.to_segment(this->context.vm_imagebase + this->context.current_virtual_opcode).first);

						this->context.current_handler_offset = opcode.read<uint16_t>(instructions.at(i + 1).get_operand_data(1));
						this->context.current_virtual_opcode += vm_opcode_delta;
						return true;
					}

					break;
				}
			}
		}
	}

	return false;
}

//void fish32::deobfuscate_prologue(std::vector<x86_instruction>& instructions)
//{
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		if ((instructions.at(i).mnemonic == FISH_MNEMONIC_STORE_STACK && instructions.at(i + 1).mnemonic == FISH_MNEMONIC_RESET) ||
//			(instructions.at(i).mnemonic == FISH_MNEMONIC_RESET && instructions.at(i + 1).mnemonic == FISH_MNEMONIC_STORE_STACK))
//		{
//			bool is_prologue = true;
//
//			for (std::size_t j = 0; j < 8; j++)
//			{
//				if (instructions.at(i + 2 + j).mnemonic != MNEMONIC_POP)
//				{
//					is_prologue = false;
//					break;
//				}
//			}
//
//			if (is_prologue &&
//				instructions.at(i + 10).mnemonic == MNEMONIC_POPF &&
//				instructions.at(i + 11).mnemonic == FISH_MNEMONIC_RESTORE_STACK)
//			{
//				this->remove_instructions(instructions, i--, 12);
//			}
//		}
//	}
//}
//
//void fish32::deobfuscate_epilogue(std::vector<x86_instruction>& instructions)
//{
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		if ((i + 8) < instructions.size() &&
//			instructions.at(i).mnemonic == MNEMONIC_PUSHF)
//		{
//			bool is_epilogue = true;
//
//			for (std::size_t j = 0; j < 7; j++)
//			{
//				if (instructions.at(i + 1 + j).mnemonic != MNEMONIC_PUSH)
//				{
//					is_epilogue = false;
//					break;
//				}
//			}
//
//			if (is_epilogue && i > 2)
//			{
//				x86_instruction leave_instruction = instructions.at(i + 8);
//
//				if (leave_instruction.mnemonic == MNEMONIC_CALL)
//				{
//					if (instructions.at(i - 2).mnemonic == MNEMONIC_PUSH &&
//						instructions.at(i - 1).mnemonic == MNEMONIC_PUSH)
//					{
//						i -= 2;
//						this->remove_instructions(instructions, i--, 10);
//					}
//				}
//				else if (leave_instruction.mnemonic == MNEMONIC_JMP ||
//					leave_instruction.mnemonic == MNEMONIC_RETN ||
//					leave_instruction.mnemonic == FISH_MNEMONIC_UNDEF ||
//					(leave_instruction.mnemonic >= MNEMONIC_JA && leave_instruction.mnemonic <= MNEMONIC_JS))
//				{
//					if (instructions.at(i - 1).mnemonic == MNEMONIC_PUSH)
//					{
//						i -= 1;
//						this->remove_instructions(instructions, i--, 9);
//					}
//				}
//			}
//		}
//	}
//	
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		if (instructions.at(i).mnemonic == FISH_MNEMONIC_LOAD_STACK ||
//			instructions.at(i).mnemonic == FISH_MNEMONIC_RESET)
//		{
//			this->remove_instructions(instructions, i--);
//		}
//	}
//}
//
//void fish32::deobfuscate_fish_addr_register(std::vector<x86_instruction>& instructions)
//{
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		/* 0: mov addr1/2,___ */
//		if (instructions.at(i).mnemonic == MNEMONIC_MOV &&
//			instructions.at(i).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//			(instructions.at(i).operands[0].base.is_type(FISH_REGISTER_ADDR_1) ||
//			instructions.at(i).operands[0].base.is_type(FISH_REGISTER_ADDR_2)))
//		{
//			bool has_base = false;
//			x86_operand_register base_register;
//
//			bool has_index = false;
//			x86_operand_register index_register;
//
//			bool has_scale = false;
//			x86_operand_scale operand_scale = OPERAND_SCALE_NONE;
//
//			bool has_data = false;
//			unsigned int operand_data = 0;
//
//			bool has_align = false;
//			unsigned int operand_align = 0;
//
//			unsigned int registers = 0;
//
//			bool skipped_opposite_addr = false;
//			unsigned int skipped_addr_index = 0;
//
//			std::size_t j = 0;
//
//			for (j = 0; j < 5; j++)
//			{
//				/* 1: ___ reg,___ */
//				if (instructions.at(i + j).operands[0].is_not_type(OPERAND_TYPE_REGISTER) ||
//					instructions.at(i + j).operands[0].base.type != instructions.at(i).operands[0].base.type ||
//					instructions.at(i + j).operands[1].is_null())
//				{
//					break;
//				}
//
//				if (instructions.at(i + j).mnemonic == FISH_MNEMONIC_ALIGN)
//				{
//					has_align = true;
//					operand_align = instructions.at(i + j).operands[1].data.dword;
//				}
//				else if (instructions.at(i + j).mnemonic == MNEMONIC_SHL)
//				{
//					registers = (has_index ? 2 : 1);
//
//					has_scale = true;
//					operand_scale = static_cast<x86_operand_scale>(instructions.at(i + j).operands[1].data.dword);
//				}
//				else if (instructions.at(i + j).operands[1].is_type(OPERAND_TYPE_IMMEDIATE))
//				{
//					has_data = true;
//					operand_data = instructions.at(i + j).operands[1].data.dword;;
//				}
//				else if (instructions.at(i + j).operands[1].is_type(OPERAND_TYPE_REGISTER))
//				{
//					if (has_base)
//					{
//						has_index = true;
//						index_register = instructions.at(i + j).operands[1].base;
//					}
//					else
//					{
//						has_base = true;
//						base_register = instructions.at(i + j).operands[1].base;
//					}
//				}
//			}
//			
//			unsigned int operand = 0xFFFFFFFF;
//			
//			if (instructions.at(i + j).operands[0].is_type(OPERAND_TYPE_MEMORY) &&
//				instructions.at(i + j).operands[0].base.type == instructions.at(i).operands[0].base.type)
//			{
//				operand = 0;
//			}
//			else if (instructions.at(i + j).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//				instructions.at(i + j).operands[0].base.type == instructions.at(i).operands[0].base.type)
//			{
//				operand = 0;
//			}
//			else if (instructions.at(i + j).operands[1].is_type(OPERAND_TYPE_MEMORY) &&
//				instructions.at(i + j).operands[1].base.type == instructions.at(i).operands[0].base.type)
//			{
//				operand = 1;
//			}
//			else if (instructions.at(i + j).operands[1].is_type(OPERAND_TYPE_REGISTER) &&
//				instructions.at(i + j).operands[1].base.type == instructions.at(i).operands[0].base.type)
//			{
//				operand = 1;
//			}
//			else if (instructions.at(i + j).mnemonic == MNEMONIC_MOV &&
//				instructions.at(i + j).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//				(instructions.at(i + j).operands[0].base.is_type(FISH_REGISTER_ADDR_1) ||
//				instructions.at(i + j).operands[0].base.is_type(FISH_REGISTER_ADDR_2)) &&
//				instructions.at(i + j).operands[0].base.type != instructions.at(i).operands[0].base.type &&
//				this->skip_opposite_addr_register(instructions, i + j, instructions.at(i).operands[0].base.type, instructions.at(i + j).operands[0].base.type, skipped_addr_index, operand))
//			{
//				skipped_opposite_addr = true;
//			}
//			else
//			{
//				continue;				
//			}
//
//			this->remove_instructions(instructions, i, j);
//
//			if (skipped_opposite_addr)
//				j = (skipped_addr_index - j) - i;
//			else
//				j = 0;
//
//			if (operand == 1 &&
//				instructions.at(i + j).mnemonic == MNEMONIC_MOV && 
//				instructions.at(i + j).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//				instructions.at(i + j).operands[1].is_type(OPERAND_TYPE_REGISTER))
//			{
//				instructions.at(i + j).mnemonic = MNEMONIC_LEA;
//				instructions.at(i + j).operands[1].set_type(OPERAND_TYPE_MEMORY, instructions.at(i + j).operands[0].base.size);
//			}
//
//			if (instructions.at(i + j).operands[operand].is_type(OPERAND_TYPE_MEMORY))
//			{
//				memset(&instructions.at(i + j).operands[operand].base, 0, sizeof(x86_operand_register));
//				memset(&instructions.at(i + j).operands[operand].index, 0, sizeof(x86_operand_register));
//				instructions.at(i + j).operands[operand].scale = OPERAND_SCALE_NONE;
//				instructions.at(i + j).operands[operand].data.dword = 0;
//
//				if (has_data)
//				{
//					instructions.at(i + j).operands[operand].data.dword = operand_data;
//
//					if (has_align)
//						instructions.at(i + j).operands[operand].data.dword += this->imagebase;
//				}
//
//				if (has_scale)
//				{
//					instructions.at(i + j).operands[operand].scale = operand_scale;
//
//					if (registers == 2)
//					{
//						instructions.at(i + j).operands[operand].index = index_register;
//						instructions.at(i + j).operands[operand].base = base_register;
//					}
//					else
//					{
//						instructions.at(i + j).operands[operand].index = base_register;
//
//						if (has_base && has_index)
//							instructions.at(i + j).operands[operand].base = index_register;
//					}
//				}
//				else if (has_base && has_index)
//				{
//					instructions.at(i + j).operands[operand].index = index_register;
//					instructions.at(i + j).operands[operand].base = base_register;
//				}
//				else if (has_base && !has_index)
//				{
//					instructions.at(i + j).operands[operand].base = base_register;
//				}
//			}
//			else
//			{
//				instructions.at(i + j).operands[operand].set_type(OPERAND_TYPE_IMMEDIATE, OPERAND_SIZE_DWORD);
//				instructions.at(i + j).operands[operand].data.dword = operand_data;
//
//				if (has_align)
//					instructions.at(i + j).operands[operand].data.dword += this->imagebase;
//			}
//		}
//	}
//}
//
//bool fish32::skip_opposite_addr_register(std::vector<x86_instruction>& instructions, std::size_t index, unsigned char old_type, unsigned char new_type, unsigned int& new_index, unsigned int& operand)
//{
//	std::size_t i = 0;
//
//	while (i < 5 &&
//		(index + i) < instructions.size() &&
//		instructions.at(index + i).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//		instructions.at(index + i).operands[0].base.type == new_type &&
//		!instructions.at(index + i).operands[1].is_null())
//	{
//		i++;
//	}
//
//	if (instructions.at(index + i).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//		instructions.at(index + i).operands[0].base.type == new_type &&
//		!instructions.at(index + i).operands[1].is_null())
//	{
//		return false;
//	}
//	if (instructions.at(index + i).operands[0].is_type(OPERAND_TYPE_MEMORY) &&
//		instructions.at(index + i).operands[0].base.type == old_type)
//	{
//		new_index = index + i;
//		operand = 0;
//		return true;
//	}
//	else if (instructions.at(index + i).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//		instructions.at(index + i).operands[0].base.type == old_type)
//	{
//		new_index = index + i;
//		operand = 0;
//		return true;
//	}
//	else if (instructions.at(index + i).operands[1].is_type(OPERAND_TYPE_MEMORY) &&
//		instructions.at(index + i).operands[1].base.type == old_type)
//	{
//		new_index = index + i;
//		operand = 1;
//		return true;
//	}
//	else if (instructions.at(index + i).operands[1].is_type(OPERAND_TYPE_REGISTER) &&
//		instructions.at(index + i).operands[1].base.type == old_type)
//	{
//		new_index = index + i;
//		operand = 1;
//		return true;
//	}
//
//	return false;
//}
//
//void fish32::deobfuscate_repeat_prefix(std::vector<x86_instruction>& instructions)
//{
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		switch (instructions.at(i).mnemonic)
//		{
//		case MNEMONIC_LODS:
//		case MNEMONIC_MOVS:
//		case MNEMONIC_STOS:
//			if (this->is_repeat_prefix(instructions, i))
//			{
//				i -= 2;
//				this->remove_instructions(instructions, i, 2);
//				
//				instructions.at(i).prefix.lock_repeat = lock_repeat_prefix::REP;
//
//				this->remove_instructions(instructions, i + 1, 2);
//			}
//
//			break;
//
//		case MNEMONIC_CMPS:
//		case MNEMONIC_SCAS:
//			if (this->is_repeat_prefix(instructions, i))
//			{
//				i -= 2;
//				this->remove_instructions(instructions, i, 2);
//
//				if (instructions.at(i + 1).mnemonic == MNEMONIC_JE)
//					instructions.at(i).prefix.lock_repeat = lock_repeat_prefix::REP;
//				else
//					instructions.at(i).prefix.lock_repeat = lock_repeat_prefix::REPNE;
//
//				this->remove_instructions(instructions, i + 1, 3);
//			}
//
//			break;
//
//		default:
//			break;
//		}
//	}
//}
//
//bool fish32::is_repeat_prefix(std::vector<x86_instruction>& instructions, std::size_t index)
//{
//	if (index >= 2)
//	{
//		/* 
//			0: cmp ecx,0x0 
//			1: je ___
//		*/
//		if (instructions.at(index - 2).mnemonic == MNEMONIC_CMP &&
//			instructions.at(index - 2).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//			instructions.at(index - 2).operands[0].base.is_type(REGISTER_ECX, OPERAND_SIZE_DWORD) &&
//			instructions.at(index - 2).operands[1].is_type(OPERAND_TYPE_IMMEDIATE) &&
//			instructions.at(index - 2).operands[1].data.dword == 0 &&
//			instructions.at(index - 1).mnemonic == MNEMONIC_JE)
//		{
//			/* 2: cmps/scas ___,___ */
//			if ((index + 3) < instructions.size() &&
//				instructions.at(index).mnemonic == MNEMONIC_CMPS ||
//				instructions.at(index).mnemonic == MNEMONIC_SCAS)
//			{
//				/*
//					3: j(n)e ___
//					4: dec ecx
//					5: jmp ___
//				*/
//				return ((instructions.at(index + 1).mnemonic == MNEMONIC_JE || 
//					instructions.at(index + 1).mnemonic == MNEMONIC_JNZ) &&
//					instructions.at(index + 2).mnemonic == MNEMONIC_DEC &&
//					instructions.at(index + 2).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//					instructions.at(index + 2).operands[0].base.is_type(REGISTER_ECX, OPERAND_SIZE_DWORD) &&
//					instructions.at(index + 3).mnemonic == MNEMONIC_JMP);
//			}
//			else if ((index + 2) < instructions.size())
//			{
//				/*
//					3: dec ecx
//					4: jmp ___
//				*/
//				return (instructions.at(index + 1).mnemonic == MNEMONIC_DEC &&
//					instructions.at(index + 1).operands[0].is_type(OPERAND_TYPE_REGISTER) &&
//					instructions.at(index + 1).operands[0].base.is_type(REGISTER_ECX, OPERAND_SIZE_DWORD) &&
//					instructions.at(index + 2).mnemonic == MNEMONIC_JMP);
//			}
//		}
//	}
//
//	return false;
//}