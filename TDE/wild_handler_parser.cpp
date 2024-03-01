#include "wild_handler_parser.hpp"
#include "wild_handler.hpp"

#include <idp.hpp>

wild_handler_parser::wild_handler_parser(wild_context& context)
	: wild_handler_tracer(context)
{

}

void wild_handler_parser::decode_virtual_handler(instruction_container& instructions, uint32_t vm_handler_offset, uint32_t& compares)
{
	compares = 0;

	uint32_t vm_delta = 0;
	get_many_bytes(this->context.vm_context + this->context.vm_handler_table_offset, &vm_delta, sizeof(uint32_t));

	if (vm_delta == this->context.vm_handler_table)
		vm_delta = 0;
	else
		vm_delta = this->context.vm_imagebase;

	uint32_t handler_offset = (vm_handler_offset * 4);
	uint32_t handler_address = *reinterpret_cast<uint32_t*>(this->context.to_segment(this->context.vm_handler_table + handler_offset).first);

	uint32_t vm_handler = handler_address + vm_delta;

	this->trace(vm_handler, compares, instructions);

	instructions.deobfuscate_wild();

	this->deobfuscate_vm_context_access(instructions);
	this->deobfuscate_unused_instructions(instructions);
	
	instructions.update_indexes();
}

void wild_handler_parser::deobfuscate_vm_context_access(instruction_container& instructions)
{
	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		/* 0: mov reg,ebp */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base_not(0, UD_R_ESP) &&
			instructions.at(i).is_operand_base_not(0, UD_R_EBP) &&
			instructions.at(i).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(1, UD_R_EBP))
		{
			ud_type base = instructions.at(i).get_base_type(0);
				
			for (std::size_t j = i + 1, operations = 1; j < instructions.size() && operations < 2; j++)
			{
				/* 1: add reg,imm32 */
				if (instructions.at(j).is_mnemonic(UD_Iadd) &&
					instructions.at(j).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
					instructions.at(j).is_operand_base(0, base) &&
					instructions.at(j).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
				{
					operations++;

					for (std::size_t k = j + 1; k < instructions.size() && operations < 3; k++)
					{
						if (instructions.at(k).is_mnemonic_not({ UD_Imovsb, UD_Imovsw, UD_Imovsd, UD_Imovsq }))
						{
							/* 2: ___ unknown ptr [reg],___ */
							if (instructions.at(k).is_operand_type(0, UD_OP_MEM) &&
								instructions.at(k).is_operand_base(0, base) &&
								instructions.at(k).has_operand_index_not(0) &&
								instructions.at(k).has_operand_scale_not(0) &&
								instructions.at(k).has_operand_data_not(0) &&
								operations == 2)
							{
								instructions.at(k).set_operand_base(0, UD_R_EBP);
								instructions.at(k).set_operand_offset(0, 32);
								instructions.at(k).set_operand_data(0, instructions.at(j).get_operand_data(1));
									
								instructions.remove(j);
								instructions.remove(i--);
								operations = 3;
							}
							/* 2: ___ ___,unknown ptr [reg] */
							else if (instructions.at(k).is_operand_type(1, UD_OP_MEM) &&
								instructions.at(k).is_operand_base(1, base) &&
								instructions.at(k).has_operand_index_not(1) &&
								instructions.at(k).has_operand_scale_not(1) &&
								instructions.at(k).has_operand_data_not(1) &&
								operations == 2)
							{
								instructions.at(k).set_operand_base(1, UD_R_EBP);
								instructions.at(k).set_operand_offset(1, 32);
								instructions.at(k).set_operand_data(1, instructions.at(j).get_operand_data(1));
									
								instructions.remove(j);
								instructions.remove(i--);
								operations = 3;
							}
							/* 2: ___ reg,___ */
							else if (instructions.at(k).is_operand_type(0, UD_OP_REG) &&
								instructions.at(k).is_operand_base(0, base))
							{
								operations++;
							}
						}
					}
				}
				/* 1: ___ reg,___ */
				else if (instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, base))
				{
					operations++;
				}
			}
		}
	}
	
	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		/* 0: mov reg,imm */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM))
		{
			uint32_t operations = 0;

			for (std::size_t j = i + 1; j < instructions.size(); j++)
			{
				/* 1: ___ reg/unknown ptr [reg],___ */
				if ((instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, instructions.at(i), 0)) ||
					(instructions.at(j).is_operand_type(0, UD_OP_MEM) &&
					(instructions.at(j).is_operand_base(0, instructions.at(i), 0) ||
					instructions.at(j).is_operand_index_by_base(0, instructions.at(i), 0))))
				{
					break;
				}

				/* 1: ___ unknown ptr [ebp+xx],reg */
				if (instructions.at(j).is_operand_type(0, UD_OP_MEM) &&
					instructions.at(j).is_operand_base(0, UD_R_EBP) &&
					instructions.at(j).has_operand_index_not(0) &&
					instructions.at(j).has_operand_scale_not(0) &&
					instructions.at(j).is_operand_type(1, UD_OP_REG) &&
					instructions.at(j).is_operand_base(1, instructions.at(i), 0))
				{
					/* 1: mov unknown ptr [ebp+xx],imm */
					instructions.at(j).set_operand_type(1, UD_OP_IMM, instructions.at(j).get_base_size(1));
					instructions.at(j).set_operand_data(1, instructions.at(i), 1);
					operations++;
				}
			}

			if (operations > 0)
				instructions.remove(i--);
		}
		/* 0: mov reg,unknown ptr [ebp+xx] */
		else if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			instructions.at(i).is_operand_type(1, UD_OP_MEM) &&
			this->context.is_key_access_instruction(instructions.at(i), true))
		{
			for (std::size_t j = i + 1; j < instructions.size(); j++)
			{
				/* 1: ___ reg/unknown ptr [reg],___ */
				if ((instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, instructions.at(i), 0)) ||
					(instructions.at(j).is_operand_type(0, UD_OP_MEM) &&
					(instructions.at(j).is_operand_base(0, instructions.at(i), 0) ||
					instructions.at(j).is_operand_index_by_base(0, instructions.at(i), 0))))
				{
					break;
				}

				/* 1: ___ unknown ptr [ebp+xx],reg */
				if (instructions.at(j).is_operand_type(0, UD_OP_MEM) &&
					instructions.at(j).is_operand_type(1, UD_OP_REG) &&
					instructions.at(j).is_operand_base(1, instructions.at(i), 0) &&
					this->context.is_key_access_instruction(instructions.at(j), true))
				{
					instructions.at(j).set_key_data(HAS_KEY_DATA_FLAG | instructions.at(i).get_operand_data(1));
				}
			}
		}
	}
}

void wild_handler_parser::deobfuscate_unused_instructions(instruction_container& instructions)
{
	bool found_handler_table = false;

	for (std::size_t i = 0, not_index = static_cast<std::size_t>(-1); i < instructions.size(); i++)
	{
		switch (instructions.at(i).get_mnemonic())
		{
		case UD_Imovsb:
		case UD_Imovsw:
		case UD_Imovsd:
		case UD_Imovsq:
			{
				instructions.at(i).set_index(1);
				this->backtrace_base_to_root(instructions, i, 0);
				this->backtrace_base_to_root(instructions, i, 1);
			}

			break;
			
		case UD_Ipushfw:
		case UD_Ipushfd:
		case UD_Ipushfq:
			{
				/* In the NOT handler, PUSHFD is used 2 instructions ahead. Always keep. */
				if (not_index != static_cast<std::size_t>(-1) && i == (not_index + 2))
					instructions.at(i).set_index(1);
				else
				{
					instructions.at(i).set_index(1);

					if (i >= 1)
					{
						if (instructions.at(i - 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }))
							this->backtrace_base_to_root(instructions, i - 1, 0);
						
						if (instructions.at(i - 1).is_operand_type(1, UD_OP_REG))
							this->backtrace_base_to_root(instructions, i - 1, 1);
					}
				}
			}

			break;

		case UD_Icall:
		case UD_Ijmp:
			{
				if (instructions.at(i).is_operand_type_not(0, UD_OP_JIMM))
					this->backtrace_base_to_root(instructions, i, 0);
			}
			
			break;
			
		case UD_Icmp:
		case UD_Itest:
			{
				/* In the NOT handler, CMP is used 1 instruction ahead. Always keep. */
				if (not_index != static_cast<std::size_t>(-1) && i == (not_index + 1))
					instructions.at(i).set_index(1);
				else
				{
					if (instructions.bounds(i, 1) && 
						(instructions.at(i + 1).is_mnemonic(UD_Ipushfd) || 
						instructions.at(i + 1).is_mnemonic_jcc()))
					{
						this->backtrace_base_to_root(instructions, i, 0);

						if (instructions.at(i).is_operand_type_not(1, UD_OP_IMM))
							this->backtrace_base_to_root(instructions, i, 1);
					}
				}
			}

			break;
			
		case UD_Ija:	case UD_Ijae:	case UD_Ijb:	case UD_Ijbe:
		case UD_Ijg:	case UD_Ijge:	case UD_Ijl:	case UD_Ijle:
		case UD_Ijz:	case UD_Ijnz:	case UD_Ijo:	case UD_Ijno:
		case UD_Ijp:	case UD_Ijnp:	case UD_Ijs:	case UD_Ijns:
			{
				instructions.at(i).set_index(1);

				if (i >= 1)
				{
					this->backtrace_base_to_root(instructions, i - 1, 0);

					if (instructions.at(i - 1).is_operand_type(1, UD_OP_REG))
						this->backtrace_base_to_root(instructions, i - 1, 1);
				}
			}

			break;

		case UD_Ipop:
			{
				instructions.at(i).set_index(1);
				
				if (instructions.at(i).is_operand_type(0, UD_OP_MEM))
					this->backtrace_base_to_root(instructions, i, 0);
			}

			break;

		case UD_Iret:
			{
				instructions.at(i).set_index(1);
			}

			break;

		default:
			{
				if (instructions.at(i).is_mnemonic(UD_Inot))
					not_index = i;
				
				if (found_handler_table)
				{
					/* ___ dword ptr [ebp+xx],reg */
					if (!this->context.initialized_crypto_offset &&
						instructions.at(i).compare_mnemonic(false, false, true) &&
						instructions.at(i).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
						instructions.at(i).is_operand_base(0, UD_R_EBP) &&
						instructions.at(i).has_operand_index_not(0) &&
						instructions.at(i).has_operand_scale_not(0) &&
						instructions.at(i).is_operand_data_not(0, this->context.vm_opcode_offset) &&
						instructions.at(i).is_operand_type(1, UD_OP_REG) &&
						!this->context.get_key(instructions.at(i).get_operand_data(0), nullptr))
					{
						this->context.initialized_crypto_offset = true;
						this->context.crypto_offset = instructions.at(i).get_operand_data<uint16_t>(0);

						instructions.remove(i--);
						continue;
					}
					/* ___ dword ptr [ebp+xx],reg */
					else if (this->context.initialized_crypto_offset &&
						instructions.at(i).compare_mnemonic(false, false, true) &&
						instructions.at(i).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
						instructions.at(i).is_operand_base(0, UD_R_EBP) &&
						instructions.at(i).has_operand_index_not(0) &&
						instructions.at(i).has_operand_scale_not(0) &&
						instructions.at(i).is_operand_data<uint16_t>(0, this->context.crypto_offset) &&
						instructions.at(i).is_operand_type(1, UD_OP_REG))
					{
						instructions.remove(i--);
						continue;
					}
				}
				
				/* 0: mov reg,dword ptr [ebp+xx] */
				if (!found_handler_table &&
					instructions.at(i).is_mnemonic(UD_Imov) &&
					instructions.at(i).is_operand_type(0, UD_OP_REG) &&
					instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
					instructions.at(i).is_operand_base(1, UD_R_EBP) &&
					instructions.at(i).has_operand_index_not(1) &&
					instructions.at(i).has_operand_scale_not(1) &&
					instructions.at(i).is_operand_data(1, this->context.vm_handler_table_offset))
				{
					found_handler_table = true;
				}
				
				/* ___ */ 
				if (instructions.at(i).is_operand_null(0))
				{
					instructions.at(i).set_index(1);
				}
				/* ___ imm */
				else if (instructions.at(i).is_operand_type(0, UD_OP_IMM))
				{
					instructions.at(i).set_index(1);
				}
				/* ___ unknown ptr [reg] */
				else if (instructions.at(i).is_operand_type(0, UD_OP_MEM))
				{
					instructions.at(i).set_index(1);
					this->backtrace_base_to_root(instructions, i, 0);

					/* ___ unknown ptr [reg],reg */
					if (instructions.at(i).is_operand_type(1, UD_OP_REG))
					{
						instructions.at(i).set_index(1);
						this->backtrace_base_to_root(instructions, i, 1);
					}
				}
				/* ___ ___,unknown ptr [reg] */
				else if (instructions.at(i).is_operand_type(1, UD_OP_MEM))
				{
					instructions.at(i).set_index(1);
					this->backtrace_base_to_root(instructions, i, 1);
				}
				/* push reg */
				else if (instructions.at(i).is_mnemonic(UD_Ipush) &&
					instructions.at(i).is_operand_type(0, UD_OP_REG))
				{
					instructions.at(i).set_index(1);
					this->backtrace_base_to_root(instructions, i, 0);
				}
				/* ___ esp */
				else if (instructions.at(i).is_operand_type(0, UD_OP_REG) &&
					instructions.at(i).is_operand_base(0, UD_R_ESP))
				{
					instructions.at(i).set_index(1);
				}
			}

			break;
		}
	}

	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		if (!instructions.at(i).get_index())
			instructions.remove(i--);
	}
}

void wild_handler_parser::backtrace_base_to_root(instruction_container& instructions, std::size_t index, uint8_t operand)
{
	if (instructions.bounds(index))
		instructions.at(index).set_index(1);

	if (index > 0 && 
		instructions.at(index).is_operand_base_family_not(operand, UD_R_ESP) && 
		instructions.at(index).is_operand_base_family_not(operand, UD_R_EBP))
	{
		ud_type base = instructions.at(index).get_base_type(operand);

		bool found_root = false;

		for (std::size_t i = (index - 1); static_cast<int32_t>(i) >= 0 && !found_root; i--)
		{
			switch (instructions.at(i).get_mnemonic())
			{
			case UD_Ipop:
				{
					/* 0: pop reg */
					if (instructions.at(i).is_operand_type(0, UD_OP_REG) &&
						instructions.at(i).is_operand_base_family(0, base))
					{
						instructions.at(i).set_index(1);
						found_root = true;
					}
				}

				break;

			case UD_Imov:
			case UD_Imovsx:
			case UD_Imovzx:
				{
					/* 0: mov(sz/zx) reg,___ */
					if (instructions.at(i).is_operand_type(0, UD_OP_REG) &&
						instructions.at(i).is_operand_base_family(0, base))
					{
						instructions.at(i).set_index(1);
						found_root = true;
						
						/* 0: mov(sz/zx) reg,reg */
						if (instructions.at(i).is_operand_type(1, UD_OP_REG) &&
							instructions.at(i).is_operand_base_not(1, UD_R_ESP) &&
							instructions.at(i).is_operand_base_not(1, UD_R_EBP))
						{
							/* 0: mov reg,reg */
							if (instructions.at(i).is_mnemonic(UD_Imov) &&
								instructions.at(i).is_operand_base(0, instructions.at(i), 1))
							{
								instructions.at(index).set_index(0);
								found_root = false;
							}
							else
							{
								this->backtrace_base_to_root(instructions, i, 1);
							}
						}
					}
				}

				break;

				/* 0: cmp/test ___,___ */
			case UD_Icmp:
			case UD_Itest:
				if (instructions.bounds(i, 1) &&
					instructions.at(i + 1).is_mnemonic_not({ UD_Ipushfw, UD_Ipushfd, UD_Ipushfq }) &&
					instructions.at(i + 1).is_mnemonic_jcc_not())
				{
					break;
				}
				
				/* 
					0: cmp/test ___,___
					1: jcc/pushf (xxxxxxxx)

					Intentionally skipping break into default case here 
				*/

			default:
				/* 0: ___ reg */
				if (instructions.at(i).is_operand_type(0, UD_OP_REG) &&
					instructions.at(i).is_operand_base_family(0, base))
				{
					instructions.at(i).set_index(1);
					
					/* 0: ___ reg,reg */
					if (instructions.at(i).is_operand_type(1, UD_OP_REG) &&
						instructions.at(i).is_operand_base_not(1, UD_R_ESP) &&
						instructions.at(i).is_operand_base_not(1, UD_R_EBP))
					{
						this->backtrace_base_to_root(instructions, i, 1);
					}
				}
				
				break;
			}
		}
	}
}