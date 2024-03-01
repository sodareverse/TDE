#include "wild_handler.hpp"
#include "instruction_emulator.hpp"

#include <idp.hpp>

#include <algorithm>

bool wild_handler::map_handler_specific(instruction_container& instructions, wild_context& context)
{
	/* Placeholder for virtual function */
	return false;
}

bool wild_handler::step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	/* Placeholder for virtual function */
	return false;
}

wild_handler::wild_handler(uint16_t index)
{
	this->id = WILD_HANDLER_INVALID;
	this->index = index;

	this->opcode_size = OPCODE_SIZE_INVALID;
	this->cmp_count = 0;
}

uint16_t wild_handler::get_id()
{
	return this->id;
}

bool wild_handler::is_flow_type()
{
	return (this->id == WILD_HANDLER_JUMP_INSIDE ||
		this->id == WILD_HANDLER_JUMP_OUTSIDE_REGISTER ||
		this->id == WILD_HANDLER_JUMP_OUTSIDE_MEMORY ||
		this->id == WILD_HANDLER_JUMP_OUTSIDE_IMMEDIATE ||
		this->id == WILD_HANDLER_RET ||
		this->id == WILD_HANDLER_CALL ||
		this->id == WILD_HANDLER_UNDEF);
}

bool wild_handler::decrypt(instruction_container& instructions, wild_context& context, uint32_t compares)
{
	this->cmp_count = compares;

	if (!this->decrypt_flow_data(instructions, context))
	{
		msg("[CodeDevirtualizer] Failed to decrypt flow data for handler %04X.\n", this->index);
		return false;
	}

	if (!this->decrypt_key_data(instructions, context))
	{
		msg("[CodeDevirtualizer] Failed to decrypt key data for handler %04X.\n", this->index);
		return false;
	}
	
	if (!this->map_handler(instructions, context))
	{
		if (!this->map_handler_specific(instructions, context))
			return false;
	}

	this->decrypt_opcode_regions(instructions, context);
	this->decrypt_opcode_size(instructions, context);
	return true;
}

bool wild_handler::decrypt_key_data(instruction_container& instructions, wild_context& context)
{
	this->decrypt_key_protection_template(instructions, context);

	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		if (context.is_key_access_instruction(instructions.at(i), false))
		{
			bool is_base_operand_key = instructions.at(i).is_operand_type(0, UD_OP_MEM);

			unsigned int operand_key = (is_base_operand_key ? 0 : 1);
			unsigned int operand_data = (is_base_operand_key ? 1 : 0);
				
			wild_handler_key key_access;
			
			key_access.id = instructions.at(i).get_operand_data<uint16_t>(operand_key);
			key_access.index = instructions.at(i).get_index();

			key_access.mnemonic = instructions.at(i).get_mnemonic();
			key_access.operand = operand_key;

			key_access.type = instructions.at(i).get_operand_type(operand_data);
			key_access.size = instructions.at(i).get_operand_size(operand_data);

			if (instructions.at(i).get_key_data() & HAS_KEY_DATA_FLAG)
			{
				if (!is_base_operand_key)
				{
					msg("[CodeDevirtualizer] Direct access key is not base operand.\n");
					return false;
				}

				key_access.direct_key_parameter = true;
				key_access.parameter = instructions.at(i).get_key_data() & 0x7FFFFFFF;

				instructions.at(i).set_key_data(0);
			}
			else
			{
				key_access.direct_key_parameter = false;
				key_access.parameter = instructions.at(i).get_params(operand_data);
			}

			instructions.remove(i--);
			this->key_accessors.push_back(key_access);
		}
	}
	
	std::sort(this->key_accessors.begin(), this->key_accessors.end());
	return true;
}

void wild_handler::decrypt_key_protection_template(instruction_container& instructions, wild_context& context)
{
	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		/* 0: mov reg,unknown ptr [ebp+xx] */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			context.is_key_access_instruction(instructions.at(i), true))
		{
			for (std::size_t j = (i + 1), binary_offset = 0; j < instructions.size(); j++)
			{
				if (instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, instructions.at(i), 0))
				{
					/* 1: ___ reg,___ */
					if (binary_offset == 0 &&
						instructions.at(j).compare_mnemonic(false, false, true))
					{
						binary_offset = j;
					}
					/*
						2: cmp reg,0x0
						3: je ___
						4: ___ unknown ptr [ebp+xx],___
					*/
					else if (binary_offset != 0 &&
						instructions.bounds(j, 3) &&
						instructions.at(j).is_mnemonic(UD_Icmp) &&
						instructions.at(j).is_operand_type(1, UD_OP_IMM) &&
						instructions.at(j).is_operand_data(1, 0) &&
						instructions.at(j + 1).is_mnemonic(UD_Ijz) &&
						instructions.at(j + 2).compare_mnemonic(false, false, true) &&
						instructions.at(j + 2).is_operand_type(0, UD_OP_MEM) &&
						context.is_key_access_instruction(instructions.at(j + 2), true) &&
						instructions.at(j + 2).is_operand_data(0, instructions.at(i), 1))
					{
						wild_handler_key key_access;
			
						key_access.id = instructions.at(j + 2).get_operand_data<uint16_t>(0);
						key_access.index = instructions.at(i).get_index();
						
						key_access.mnemonic = instructions.at(j + 2).get_mnemonic();
						key_access.operand = 0;

						key_access.type = instructions.at(j + 2).get_operand_type(1);
						key_access.size = instructions.at(j + 2).get_operand_size(0);

						key_access.direct_key_parameter = false;
						key_access.parameter = instructions.at(j + 2).get_params(1);
						
						key_access.condition = [](wild_context const& context, wild_handler_key const& key_accessor) -> bool
						{
							uint32_t key_data = 0;

							if (!context.get_key(key_accessor.id, &key_data))
								return false;
							
							return ((key_data & 1) != 0);
						};

						this->key_accessors.push_back(key_access);
						
						instructions.remove(j, 3);
						instructions.remove(binary_offset);
						instructions.remove(i--);
						break;
					}
					else
					{
						break;
					}
				}
			}
		}
	}
}

std::size_t wild_handler::find_first_key_after(std::size_t index)
{
	for (std::size_t i = 0; i < this->key_accessors.size(); i++)
	{
		if (this->key_accessors.at(i).index >= index)
			return i;
	}

	return static_cast<std::size_t>(-1);
}

std::size_t wild_handler::find_last_key_before(std::size_t index)
{
	for (std::size_t i = (this->key_accessors.size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		if (this->key_accessors.at(i).index <= index)
			return i;
	}
		
	return static_cast<std::size_t>(-1);
}
	
void wild_handler::decrypt_opcode_size(instruction_container& instructions, wild_context& context)
{
	if (instructions.back().is_mnemonic(UD_Iret))
		this->opcode_size = OPCODE_SIZE_RETN;
	else if (instructions.back().is_mnemonic(UD_Ijmp))
	{
		std::size_t index = (instructions.size() - 2);

		if (context.is_opcode_access_instruction(instructions.at(index)))
		{
			if (instructions.at(index).is_mnemonic(UD_Isub))
				this->opcode_size = OPCODE_SIZE_SUB;
			else if (instructions.at(index).is_mnemonic(UD_Iadd))
				this->opcode_size = instructions.at(index).get_operand_data<uint16_t>(1);
		}
	}
}

void wild_handler::decrypt_opcode_regions(instruction_container& instructions, wild_context& context)
{
	for (std::size_t i = 0; i < instructions.size(); i++)
	{
		/* 0: mov reg,dword ptr [ebp+xx] */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			context.is_opcode_access_instruction(instructions.at(i)))
		{
			uint16_t opcode_offset = 0xFFFF;

			ud_type type = UD_NONE;
			ud_size size = UD_SIZE_NONE;

			std::size_t offset = 0;

			for (std::size_t j = i + 1; j < instructions.size(); j++)
			{
				if (instructions.at(j).is_mnemonic(UD_Iadd) &&
					instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, instructions.at(i), 0) &&
					instructions.at(j).is_operand_type(1, UD_OP_IMM))
				{
					opcode_offset = instructions.at(j).get_operand_data<uint16_t>(1);
				}
				else if (instructions.at(j).is_mnemonic({ UD_Imov, UD_Imovzx }) &&
					instructions.at(j).is_operand_type(1, UD_OP_MEM) &&
					instructions.at(j).is_operand_base(1, instructions.at(i), 0))
				{
					type = instructions.at(j).get_base_size_type(0, UD_SIZE_DWORD);
					size = instructions.at(j).get_operand_size(1);
					offset = j;
					break;
				}
				else if (instructions.at(j).is_mnemonic(UD_Imov) &&
					instructions.at(j).is_operand_type(0, UD_OP_REG) &&
					instructions.at(j).is_operand_base(0, instructions.at(i), 0))
				{
					break;
				}
			}
			
			if (opcode_offset != 0xFFFF && type != UD_NONE)
			{
				std::size_t index = offset;
				std::vector<std::size_t> indexes;

				while (instructions.bounds(++index) && 
					index < this->flow_read_index)
				{
					for (std::size_t j = 0; j < this->key_accessors.size(); j++)
					{
						wild_handler_key& key = this->key_accessors.at(j);

						if (key.index == index)
						{
							if (key.type == UD_OP_REG &&
								instructions.at(offset).is_operand_base_family(0, static_cast<ud_type>(key.parameter)))
							{
								indexes.push_back(index);
							}

							break;
						}
					}
					
					if (instructions.at(index).is_mnemonic(UD_Imov) &&
						instructions.at(index).is_operand_type(0, UD_OP_REG) &&
						instructions.at(index).is_operand_base_family(0, instructions.at(i), 0))
					{
						break;
					}
				}

				if (!indexes.empty())
					this->opcode_regions.push_back({ opcode_offset, size, indexes.front(), indexes.back() });
			}
		}
	}
}

bool wild_handler::map_handler(instruction_container& instructions, wild_context& context)
{
	return (this->map_handler_jmp(instructions, context) ||
		this->map_handler_jcc(instructions, context) ||
		this->map_handler_retn(instructions, context) ||
		this->map_handler_undef(instructions, context) ||
		this->map_handler_lods(instructions, context) ||
		this->map_handler_stos(instructions, context) ||
		this->map_handler_scas(instructions, context) ||
		this->map_handler_cmps(instructions, context) ||
		this->map_handler_movs(instructions, context) ||
		this->map_handler_eflags(instructions, context) ||
		this->map_handler_stack(instructions, context) ||
		this->map_handler_reset_eflags(instructions, context) ||
		this->map_handler_reset(instructions, context) ||
		this->map_handler_crypt(instructions, context));
}

bool wild_handler::map_handler_jmp(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 16) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Ishl) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(5).is_mnemonic(UD_Iadd) &&
		instructions.at(6).is_mnemonic(UD_Imov) &&
		instructions.at(7).is_mnemonic(UD_Imov) &&
		instructions.at(8).is_mnemonic(UD_Iadd) &&
		instructions.at(9).is_mnemonic(UD_Imov) &&
		instructions.at(10).is_mnemonic(UD_Imov) &&
		instructions.at(11).is_mnemonic(UD_Iand) &&
		instructions.at(12).is_mnemonic(UD_Icmp) &&
		instructions.at(13).is_mnemonic(UD_Ijz) &&
		instructions.at(14).is_mnemonic(UD_Iand) &&
		instructions.at(15).is_mnemonic(UD_Isub) &&
		instructions.at(16).is_mnemonic(UD_Ijmp))
	{
		this->id = WILD_HANDLER_JUMP_INSIDE;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		this->opcode_offsets[1] = instructions.at(8).get_loword(1);
		return true;
	}
	else if (instructions.bounds(0, 10) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(4).is_operand_base(1, instructions.at(3), 0) &&
		instructions.at(5).is_mnemonic(UD_Imov) &&
		instructions.at(6).is_mnemonic(UD_Iadd) &&
		instructions.at(7).is_mnemonic(UD_Imov) &&
		instructions.at(8).is_mnemonic(UD_Iadd) &&
		instructions.at(9).is_mnemonic(UD_Imov) &&
		instructions.at(9).is_operand_base(1, instructions.at(4), 0) &&
		instructions.at(10).is_mnemonic(UD_Imov))
	{
		this->id = WILD_HANDLER_JUMP_OUTSIDE_REGISTER;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		return true;
	}
	else if (instructions.bounds(0, 11) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(4).is_operand_base(1, instructions.at(3), 0) &&
		instructions.at(5).is_mnemonic(UD_Imov) &&
		instructions.at(5).is_operand_base(1, instructions.at(4), 0) &&
		instructions.at(6).is_mnemonic(UD_Imov) &&
		instructions.at(7).is_mnemonic(UD_Iadd) &&
		instructions.at(8).is_mnemonic(UD_Imov) &&
		instructions.at(9).is_mnemonic(UD_Iadd) &&
		instructions.at(10).is_mnemonic(UD_Imov) &&
		instructions.at(11).is_mnemonic(UD_Imov))
	{
		this->id = WILD_HANDLER_JUMP_OUTSIDE_MEMORY;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		return true;
	}
	else if (instructions.bounds(0, 18) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(5).is_mnemonic(UD_Iadd) &&
		instructions.at(6).is_mnemonic(UD_Imov) &&
		instructions.at(7).is_mnemonic(UD_Iadd) &&
		instructions.at(7).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD) &&
		instructions.at(7).is_operand_base(1, UD_R_ESP) &&
		instructions.at(8).is_mnemonic(UD_Imov) &&
		instructions.at(9).is_mnemonic(UD_Imov) &&
		instructions.at(10).is_mnemonic(UD_Ipop) &&
		instructions.at(11).is_mnemonic(UD_Ipop) &&
		instructions.at(12).is_mnemonic(UD_Ipop) &&
		instructions.at(13).is_mnemonic(UD_Ipop) &&
		instructions.at(14).is_mnemonic(UD_Ipop) &&
		instructions.at(15).is_mnemonic(UD_Ipop) &&
		instructions.at(16).is_mnemonic(UD_Ipop) &&
		instructions.at(17).is_mnemonic({ UD_Ipopfw, UD_Ipopfd, UD_Ipopfq }) &&
		instructions.at(18).is_mnemonic(UD_Iret))
	{
		this->id = WILD_HANDLER_JUMP_OUTSIDE_IMMEDIATE;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		return true;
	}

	return false;
}
	
bool wild_handler::map_handler_jcc(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 14) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Imov) &&
		instructions.at(2).is_mnemonic(UD_Iadd) &&
		instructions.at(3).is_mnemonic(UD_Imov) &&
		instructions.at(4).is_mnemonic(UD_Iadd) &&
		instructions.at(5).is_mnemonic(UD_Imov) &&
		instructions.at(6).is_mnemonic(UD_Imov) &&
		instructions.at(7).is_mnemonic(UD_Iadd) &&
		instructions.at(8).is_mnemonic(UD_Imov) &&
		instructions.at(9).is_mnemonic(UD_Icmp) &&
		instructions.at(10).is_mnemonic(UD_Ijz) &&
		instructions.at(11).is_mnemonic(UD_Icmp) &&
		instructions.at(12).is_mnemonic(UD_Ijz) &&
		instructions.at(13).is_mnemonic(UD_Icmp) &&
		instructions.at(14).is_mnemonic(UD_Ijnz))
	{
		std::size_t index = (instructions.size() - 25);

		if (instructions.bounds(0, 25) &&
			instructions.find_mnemonic_index(UD_Iret, index))
		{
			this->id = WILD_HANDLER_JCC_OUTSIDE;
		}
		else
		{
			this->id = WILD_HANDLER_JCC_INSIDE;
		}
		
		this->opcode_offsets[0] = instructions.at(7).get_loword(1);
		return this->parse_jcc_parameters(instructions, context);
	}

	return false;
}

bool wild_handler::map_handler_retn(instruction_container& instructions, wild_context& context)
{
	for (std::size_t i = 2; i < 15 && i < instructions.size(); i++)
	{
		/* 0: std */
		if (instructions.at(i).is_mnemonic(UD_Istd))
		{
			this->id = WILD_HANDLER_RET;
			this->opcode_offsets[0] = instructions.at(1).get_loword(1);
			return true;
		}
	}
	
	return false;
}

bool wild_handler::map_handler_undef(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 10) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Icmp) &&
		instructions.at(4).is_mnemonic(UD_Ijz) &&
		instructions.at(5).is_mnemonic(UD_Icmp) &&
		instructions.at(6).is_mnemonic(UD_Ijz) &&
		instructions.at(7).is_mnemonic(UD_Imov) &&
		instructions.at(8).is_mnemonic(UD_Iadd) &&
		instructions.at(9).is_mnemonic(UD_Imov) &&
		instructions.at(10).is_mnemonic(UD_Iadd))
	{
		this->id = WILD_HANDLER_UNDEF;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		this->opcode_offsets[1] = instructions.at(8).get_loword(1);
		return true;
	}
	
	return false;
}
	
bool wild_handler::map_handler_lods(instruction_container& instructions, wild_context& context)
{
	std::size_t pop_index = 18;

	/*
		0: mov ___,___
		1: and ___,___
		2: pop ___
	*/
	if (instructions.find_mnemonic_index(UD_Ipop, pop_index) &&
		instructions.at(pop_index - 2).is_mnemonic(UD_Imov) &&
		instructions.at(pop_index - 1).is_mnemonic(UD_Iand))
	{
		std::size_t index = 2;
		
		/* 0: push reg */
		if (instructions.find_mnemonic_index(UD_Ipush, index) &&
			index < 15 &&
			instructions.at(index).is_operand_type(0, UD_OP_REG))
		{
			std::size_t memory_index = static_cast<std::size_t>(-1);

			for (std::size_t i = index; i < 16 && i < instructions.size(); i++)
			{
				/* 0: mov unknown ptr [reg],___ */
				if (instructions.at(i).is_mnemonic(UD_Imov) &&
					instructions.at(i).is_operand_type(0, UD_OP_MEM))
				{
					memory_index = i;
					break;
				}
			}
			
			/*
				3: cmp ___,0x0
				4: je  ___
				5: sub ___,___
			*/
			if (memory_index != static_cast<std::size_t>(-1) &&
				instructions.bounds(pop_index, 3) &&
				instructions.at(pop_index + 1).is_mnemonic(UD_Icmp) &&
				instructions.at(pop_index + 1).is_operand_type(1, UD_OP_IMM) &&
				instructions.at(pop_index + 1).is_operand_data(1, 0) &&
				instructions.at(pop_index + 2).is_mnemonic(UD_Ijz) &&
				instructions.at(pop_index + 3).is_mnemonic(UD_Isub))
			{
				if (instructions.at(memory_index).is_operand_base_not(0, instructions.at(index), 0))
				{
					switch (instructions.at(pop_index + 3).get_operand_data(1))
					{
					case 1:
						this->id = WILD_HANDLER_LODSB;
						return true;

					case 2:
						this->id = WILD_HANDLER_LODSW;
						return true;

					case 4:
						this->id = WILD_HANDLER_LODSD;
						return true;

					default:
						break;
					}
				}
			}
		}
	}

	return false;
}

bool wild_handler::map_handler_stos(instruction_container& instructions, wild_context& context)
{
	std::size_t pop_index = 18;

	/*
		0: mov ___,___
		1: and ___,___
		2: pop ___
	*/
	if (instructions.find_mnemonic_index(UD_Ipop, pop_index) &&
		instructions.at(pop_index - 2).is_mnemonic(UD_Imov) &&
		instructions.at(pop_index - 1).is_mnemonic(UD_Iand))
	{
		std::size_t index = 2;
		
		/* 0: push reg */
		if (instructions.find_mnemonic_index(UD_Ipush, index) &&
			index < 15 &&
			instructions.at(index).is_operand_type(0, UD_OP_REG))
		{
			std::size_t memory_index = static_cast<std::size_t>(-1);

			for (std::size_t i = index; i < 16 && i < instructions.size(); i++)
			{
				/* 0: mov unknown ptr [reg],___ */
				if (instructions.at(i).is_mnemonic(UD_Imov) &&
					instructions.at(i).is_operand_type(0, UD_OP_MEM))
				{
					memory_index = i;
					break;
				}
			}
			
			/*
				3: cmp ___,0x0
				4: je  ___
				5: sub ___,___
			*/
			if (memory_index != static_cast<std::size_t>(-1) &&
				instructions.bounds(pop_index, 3) &&
				instructions.at(pop_index + 1).is_mnemonic(UD_Icmp) &&
				instructions.at(pop_index + 1).is_operand_type(1, UD_OP_IMM) &&
				instructions.at(pop_index + 1).is_operand_data(1, 0) &&
				instructions.at(pop_index + 2).is_mnemonic(UD_Ijz) &&
				instructions.at(pop_index + 3).is_mnemonic(UD_Isub))
			{
				if (instructions.at(memory_index).is_operand_base(0, instructions.at(index), 0))
				{
					switch (instructions.at(pop_index + 3).get_operand_data(1))
					{
					case 1:
						this->id = WILD_HANDLER_STOSB;
						return true;

					case 2:
						this->id = WILD_HANDLER_STOSW;
						return true;

					case 4:
						this->id = WILD_HANDLER_STOSD;
						return true;

					default:
						break;
					}
				}
			}
		}
	}

	return false;
}

bool wild_handler::map_handler_scas(instruction_container& instructions, wild_context& context)
{
	std::size_t index = 10;

	/*
		11: sub ___,___
		12: pushfd
	*/
	if (instructions.find_mnemonic_index(UD_Ipushfd, index) &&
		instructions.at(index - 1).is_mnemonic(UD_Isub))
	{
		/* 
			0: cmp ___,0x0
			1: je  ___
			2: sub ___,imm
		*/
		if (instructions.find_mnemonic_index(UD_Icmp, index) &&
			instructions.bounds(index, 2) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index).is_operand_data(1, 0) &&
			instructions.at(index + 1).is_mnemonic(UD_Ijz) &&
			instructions.at(index + 2).is_mnemonic(UD_Isub) &&
			instructions.at(index + 2).is_operand_type(1, UD_OP_IMM))
		{
			switch (instructions.at(index + 2).get_operand_data(1))
			{
			case 1:
				this->id = WILD_HANDLER_SCASB;
				return true;

			case 2:
				this->id = WILD_HANDLER_SCASW;
				return true;

			case 4:
				this->id = WILD_HANDLER_SCASD;
				return true;

			default:
				break;
			}
		}
	}

	return false;
}

bool wild_handler::map_handler_cmps(instruction_container& instructions, wild_context& context)
{
	std::size_t index = 10;

	/*
		0: cmp ___,___
		1: pushfd
	*/
	if (instructions.find_mnemonic_index(UD_Ipushfd, index) &&
		instructions.at(index - 1).is_mnemonic(UD_Icmp))
	{
		/* 
			0: cmp ___,0x0
			1: je  ___
			2: sub ___,imm
			3: sub ___,___
		*/
		if (instructions.find_mnemonic_index(UD_Icmp, index) &&
			instructions.bounds(index, 3) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index).is_operand_data(1, 0) &&
			instructions.at(index + 1).is_mnemonic(UD_Ijz) &&
			instructions.at(index + 2).is_mnemonic(UD_Isub) &&
			instructions.at(index + 2).is_operand_type(1, UD_OP_IMM) &&
			instructions.at(index + 3).is_mnemonic(UD_Isub))
		{
			switch (instructions.at(index + 2).get_operand_data(1))
			{
			case 1:
				this->id = WILD_HANDLER_CMPSB;
				return true;

			case 2:
				this->id = WILD_HANDLER_CMPSW;
				return true;

			case 4:
				this->id = WILD_HANDLER_CMPSD;
				return true;

			default:
				break;
			}
		}
	}

	return false;
}

bool wild_handler::map_handler_movs(instruction_container& instructions, wild_context& context)
{
	std::size_t memory_index = static_cast<std::size_t>(-1);

	for (std::size_t i = 10; i < 25 && i < instructions.size(); i++)
	{
		/* 0: mov unknown ptr [reg],___ */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_MEM))
		{
			memory_index = i;
			break;
		}
	}

	std::size_t index = memory_index;
			
	/*
		0: cmp ___,0x0
		1: je  ___
		2: sub ___,___
		3: sub ___,imm
	*/
	if ((memory_index != static_cast<std::size_t>(-1) &&
		instructions.find_mnemonic_index(UD_Icmp, index) &&
		instructions.bounds(index, 3) &&
		((index - memory_index) >= 10 && (index - memory_index) <= 20)) &&
		instructions.at(index).is_operand_type(1, UD_OP_IMM) &&
		instructions.at(index).is_operand_data(1, 0) &&
		instructions.at(index + 1).is_mnemonic(UD_Ijz) &&
		instructions.at(index + 2).is_mnemonic(UD_Isub) &&
		instructions.at(index + 3).is_mnemonic(UD_Isub) &&
		instructions.at(index + 3).is_operand_type(1, UD_OP_IMM))
	{
		switch (instructions.at(index + 3).get_operand_data(1))
		{
		case 1:
			this->id = WILD_HANDLER_MOVSB;
			return true;

		case 2:
			this->id = WILD_HANDLER_MOVSW;
			return true;

		case 4:
			this->id = WILD_HANDLER_MOVSD;
			return true;

		default:
			break;
		}
	}

	return false;
}
	
bool wild_handler::map_handler_eflags(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 8) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(3).is_operand_type(1, UD_OP_REG) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(5).is_mnemonic(UD_Iadd) &&
		instructions.at(6).is_mnemonic(UD_Imov) &&
		instructions.at(7).is_mnemonic(UD_Icmp) &&
		instructions.at(8).is_mnemonic(UD_Ijnz))
	{
		this->id = WILD_HANDLER_EFLAGS;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		this->opcode_offsets[1] = instructions.at(5).get_loword(1);
		return this->parse_eflags_parameters(instructions, context);
	}
	else
	{
		std::vector<std::pair<std::size_t, ud_instruction>> matches;

		for (std::size_t i = 0; i < instructions.size(); i++)
		{
			/* 0: mov reg,dword ptr [ebp+xx] */
			if (instructions.at(i).is_mnemonic(UD_Imov) &&
				instructions.at(i).is_operand_type(0, UD_OP_REG) &&
				context.is_opcode_access_instruction(instructions.at(i)))
			{
				std::size_t index = i;
				ud_instruction instruction;

				/* 0: add reg,___ */
				if (!instructions.find_index_by_register_base(instructions.at(i).get_base_type(0), ++index, instruction) ||
					instruction.is_mnemonic_not(UD_Iadd))
				{
					continue;
				}
				
				/* 1: movzx ___,unknown ptr [reg] */
				if (!instructions.find_index_by_memory_base(instructions.at(i).get_base_type(0), 1, ++index, instruction) ||
					instruction.is_mnemonic_not(UD_Imovzx))
				{
					continue;
				}
				
				ud_type data_base = instruction.get_base_type(0);
				
				/* 2: add reg,ebp */
				if (!instructions.find_index_by_register_base(data_base, ++index, instruction) ||
					instruction.is_mnemonic_not(UD_Iadd) ||
					instruction.is_operand_type_not(1, UD_OP_REG, UD_SIZE_DWORD) ||
					instruction.is_operand_base_not(1, UD_R_EBP))
				{
					continue;
				}
				
				/* 3: ___ unknown ptr [reg] */
				if (!instructions.find_index_by_memory_base(data_base, 0, ++index, instruction) ||
					index > 20)
				{
					continue;
				}

				matches.push_back(std::make_pair(index, instruction));
			}
		}
		
		if (!matches.empty())
		{
			for (std::size_t i = 0; i < 2; i++)
			{
				uint32_t offset_count = 0;
				uint32_t operation_count = 0;

				for (std::size_t j = 0; j < matches.size(); j++)
				{
					/* 3: sub/add unknown ptr [reg],0x4 */
					if (matches.at(j).second.is_mnemonic(i == 0 ? UD_Isub : UD_Iadd) &&
						matches.at(j).second.is_operand_type(1, UD_OP_IMM) &&
						matches.at(j).second.is_operand_data(1, 4))
					{
						offset_count++;
					}
					/* 3: push/pop unknown ptr [reg] */
					else if (matches.at(j).second.is_mnemonic(i == 0 ? UD_Ipush : UD_Ipop))
					{
						if (matches.at(j).second.is_mnemonic(UD_Ipush) &&
							instructions.bounds(matches.at(j).first, 1) &&
							instructions.at(matches.at(j).first + 1).is_mnemonic({ UD_Ipopfw, UD_Ipopfd, UD_Ipopfq }))
						{
							break;
						}

						operation_count++;
					}
				}

				if (offset_count == 1 && operation_count == 1)
				{
					this->id = (i == 0 ? WILD_HANDLER_PUSHFD : WILD_HANDLER_POPFD);
					return true;
				}
			}
		}
	}

	return false;
}
	
//bool wild_handler::map_handler_eflags(instruction_container& instructions, wild_context& context)
//{
//	if (instructions.bounds(0, 8) &&
//		instructions.at(0).is_mnemonic(UD_Imov) &&
//		instructions.at(1).is_mnemonic(UD_Iadd) &&
//		instructions.at(2).is_mnemonic(UD_Imov) &&
//		instructions.at(3).is_mnemonic(UD_Iadd) &&
//		instructions.at(3).is_operand_type(1, UD_OP_REG) &&
//		instructions.at(4).is_mnemonic(UD_Imov) &&
//		instructions.at(5).is_mnemonic(UD_Iadd) &&
//		instructions.at(6).is_mnemonic(UD_Imov) &&
//		instructions.at(7).is_mnemonic(UD_Icmp) &&
//		instructions.at(8).is_mnemonic(UD_Ijnz))
//	{
//		this->id = WILD_HANDLER_EFLAGS;
//		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
//		this->opcode_offsets[1] = instructions.at(5).get_loword(1);
//		return this->parse_eflags_parameters(instructions, context);
//	}
//	else
//	{
//		const unsigned int eflag_types = 2;
//
//		unsigned int read_opcode_instructions = 0;
//		std::pair<std::size_t, ud_type> opcode_read_instruction[eflag_types];
//
//		for (std::size_t i = 0; i < 10 && i < instructions.size() && read_opcode_instructions < 2; i++)
//		{
//			if (context.is_opcode_access_instruction(instructions.at(i)))
//			{
//				if (!read_opcode_instructions)
//					opcode_read_instruction[0] = std::make_pair(i, instructions.at(i).get_base_type(0));
//				else
//					opcode_read_instruction[1] = std::make_pair(i, instructions.at(i).get_base_type(0));
//
//				read_opcode_instructions++;
//			}
//		}
//
//		if (read_opcode_instructions < eflag_types)
//			return false;
//
//		ud_instruction eflag_instructions[eflag_types];
//
//		for (std::size_t i = 0; i < eflag_types; i++)
//		{
//			std::size_t index = opcode_read_instruction[i].first;
//
//			/* 0: add reg,___ */
//			if (!instructions.find_index_by_register_base(opcode_read_instruction[i].second, ++index, eflag_instructions[i]) ||
//				eflag_instructions[i].is_mnemonic_not(UD_Iadd))
//			{
//				return false;
//			}
//
//			/* 1: movzx ___,unknown ptr [reg] */
//			if (!instructions.find_index_by_memory_base(opcode_read_instruction[i].second, 1, ++index, eflag_instructions[i]) ||
//				eflag_instructions[i].is_mnemonic_not({ UD_Imov, UD_Imovzx }))
//			{
//				return false;
//			}
//
//			/* For TIGER */
//			if (eflag_instructions[i].is_mnemonic(UD_Imov))
//			{
//				bool found = false;
//
//				for (std::size_t j = std::max(opcode_read_instruction[0].first, opcode_read_instruction[1].first) + 1; j < 10 && j < instructions.size(); j++)
//				{
//					if (context.is_opcode_access_instruction(instructions.at(j)))
//					{
//						opcode_read_instruction[i--] = std::make_pair(j, instructions.at(j).get_base_type(0));
//						found = true;
//						break;
//					}
//				}
//
//				if (found)
//					continue;
//			}
//
//			ud_type opcode_base = eflag_instructions[i].get_base_type(0);
//
//			/* 2: add reg,ebp */
//			if (!instructions.find_index_by_register_base(opcode_base, ++index, eflag_instructions[i]) ||
//				eflag_instructions[i].is_mnemonic_not(UD_Iadd) ||
//				eflag_instructions[i].is_operand_type_not(1, UD_OP_REG, UD_SIZE_DWORD) ||
//				eflag_instructions[i].is_operand_base_not(1, UD_R_EBP))
//			{
//				return false;
//			}
//
//			/* 3: ___ unknown ptr [reg] */
//			if (!instructions.find_index_by_memory_base(opcode_base, 0, ++index, eflag_instructions[i]) ||
//				index > 20)
//			{
//				return false;
//			}
//		}
//
//		for (std::size_t i = 0; i < 2; i++)
//		{
//			bool found = true;
//
//			for (std::size_t j = 0; j < eflag_types; j++)
//			{
//				/* 3: sub/add unknown ptr [reg],___ */
//				if (eflag_instructions[j].is_mnemonic(i == 0 ? UD_Isub : UD_Iadd))
//				{
//					/* 3: sub/add unknown ptr [reg],0x4 */
//					if (eflag_instructions[j].is_operand_type_not(1, UD_OP_IMM) ||
//						eflag_instructions[j].is_operand_data_not(1, 4))
//					{
//						found = false;
//						break;
//					}
//				}
//				/* 3: push/pop unknown ptr [reg] */
//				else if (eflag_instructions[j].is_mnemonic_not(i == 0 ? UD_Ipush : UD_Ipop))
//				{
//					found = false;
//					break;
//				}
//			}
//
//			if (found)
//			{
//				this->id = (i == 0 ? WILD_HANDLER_PUSHFD : WILD_HANDLER_POPFD);
//				this->opcode_offsets[0] = instructions.at(3).get_loword(1);
//				return true;
//			}
//		}
//	}
//
//	return false;
//}

bool wild_handler::map_handler_stack(instruction_container& instructions, wild_context& context)
{
	/*
		0: mov ___,___
		1: add ___,___
		2: movzx ___,___
		3: add ___,___
		4: mov esp,___
	*/
	if (instructions.bounds(0, 4) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imovzx) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(4).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
		instructions.at(4).is_operand_base(0, UD_R_ESP))
	{
		this->id = WILD_HANDLER_LOAD_STACK;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		return true;
	}
	/*
		0: mov ___,___
		1: add ___,___
		2: movzx ___,___
		3: add ___,___
		4: mov ___,esp
	*/
	else if (instructions.bounds(0, 4) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imovzx) &&
		instructions.at(3).is_mnemonic(UD_Iadd) &&
		instructions.at(4).is_mnemonic(UD_Imov) &&
		instructions.at(4).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD) &&
		instructions.at(4).is_operand_base(1, UD_R_ESP))
	{
		this->id = WILD_HANDLER_STORE_STACK;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		return true;
	}
	else
	{
		for (std::size_t i = 3; i < 9 && i < instructions.size(); i++)
		{
			/* 0: add esp,reg */
			if (instructions.at(i).is_mnemonic(UD_Iadd) &&
				instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
				instructions.at(i).is_operand_base(0, UD_R_ESP) &&
				instructions.at(i).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD) &&
				instructions.at(i).is_operand_base_not(1, UD_R_ESP))
			{
				this->id = WILD_HANDLER_RESTORE_STACK;
				this->opcode_offsets[0] = instructions.at(4).get_loword(1);
				return true;
			}
		}
	}

	return false;
}

bool wild_handler::map_handler_reset_eflags(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(0).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
		instructions.at(0).is_operand_base(0, UD_R_EBP) &&
		instructions.at(0).is_operand_type(1, UD_OP_IMM) &&
		instructions.at(0).is_operand_data(1, 0) &&
		this->flow_read_index == 1)
	{
		this->id = WILD_HANDLER_RESET_EFLAGS;
		return true;
	}
	
	return false;
}

bool wild_handler::map_handler_reset(instruction_container& instructions, wild_context& context)
{
	for (std::size_t i = 0; i < 5 && i < instructions.size(); i++)
	{
		/* 0: mov ___,___ */
		if (instructions.at(i).is_mnemonic_not(UD_Imov))
			return false;
	}
	
	this->id = WILD_HANDLER_RESET;
	return true;
}

bool wild_handler::map_handler_crypt(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 6))
	{
		ud_type base = UD_NONE;
		uint32_t opcodes = 0;

		for (std::size_t i = 0; i < 5 && i < instructions.size(); i++)
		{
			/* 0: ___ unknown ptr [reg],___ */
			if (instructions.at(i).is_operand_type(0, UD_OP_MEM))
				return false;
			
			/* 0: mov ___,unknown ptr [reg] */
			if (instructions.at(i).is_mnemonic(UD_Imov) &&
				instructions.at(i).is_operand_type(1, UD_OP_MEM))
			{
				/* 0: mov ___,dword ptr [ebp+xx] */
				if (context.is_opcode_access_instruction(instructions.at(i)))
				{
					opcodes++;
				}
				/* 0: mov reg,dword ptr [ebp+xx] */
				else if (instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
					instructions.at(i).is_operand_base(1, UD_R_EBP) &&
					!context.get_key(instructions.at(i).get_operand_data(1), nullptr))
				{
					base = instructions.at(i).get_base_type(0);
				}
			}
		}

		if (opcodes == 1 &&
			instructions.at(5).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(5).is_operand_type(1, UD_OP_REG) &&
			instructions.at(5).is_operand_base(1, base))
		{
			this->id = WILD_HANDLER_CRYPT;
			
			for (std::size_t i = 0; i < 5; i++)
			{
				if (instructions.at(i).is_mnemonic(UD_Imov) &&
					instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
					!context.is_opcode_access_instruction(instructions.at(i)))
				{
					this->opcode_offsets[1] = instructions.at(i).get_operand_data<uint16_t>(1);
				}
				else if (instructions.at(i).is_mnemonic(UD_Iadd) &&
					instructions.at(i).is_operand_type(1, UD_OP_IMM))
				{
					this->opcode_offsets[0] = instructions.at(i).get_operand_data<uint16_t>(1);
				}
			}

			return true;
		}
	}
	
	return false;
}

bool wild_handler::parse_jcc_parameters(instruction_container& instructions, wild_context& context)
{
	if (!context.initialized_jcc_types)
	{
		ud_type base = UD_NONE;

		for (std::size_t i = 0, index = 8; i < 17; i++)
		{
			while (true)
			{
				if (!instructions.find_mnemonic_index(UD_Icmp, ++index))
					return false;

				if (instructions.at(index).is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE))
				{
					if (!base)
					{
						base = instructions.at(index).get_base_type(0);
						break;
					}
					else if (instructions.at(index).is_operand_base(0, base))
						break;
				}
			}

			static const ud_mnemonic_code jcc_type_table[] = 
			{
				UD_Ijz,		UD_Ijle,	UD_Ijnz,	UD_Ija, 
				UD_Ijae,	UD_Ijb, 	UD_Ijbe,	UD_Ijg,
				UD_Ijge,	UD_Ijl,		UD_Ijcxz, 	UD_Ijno,
				UD_Ijnp,	UD_Ijns,	UD_Ijo, 	UD_Ijp,
				UD_Ijs 
			};
			
			context.set_jcc_mnemonic(instructions.at(index).get_operand_data<uint8_t>(1), jcc_type_table[i]);
		}
		
		context.initialized_jcc_types = true;
	}

	for (std::size_t i = 40, occurances = 0; i < instructions.size(); i++)
	{
		if (instructions.bounds(i, 1) &&
			instructions.at(i).is_mnemonic(UD_Imov) &&
			context.is_opcode_access_instruction(instructions.at(i)))
		{
			if (occurances == 0)
				this->opcode_offsets[1] = instructions.at(i + 1).get_operand_data(1);
			else if (occurances == 1)
			{
				this->opcode_offsets[2] = instructions.at(i + 1).get_operand_data(1);
				return true;
			}

			occurances++;
		}
	}

	return false;
}

bool wild_handler::parse_eflags_parameters(instruction_container& instructions, wild_context& context)
{
	if (!context.initialized_eflags_types)
	{
		ud_type base = UD_NONE;

		for (std::size_t i = 0, index = 5; i < 7; i++)
		{
			while (true)
			{
				if (!instructions.find_mnemonic_index(UD_Icmp, ++index))
					return false;

				if (instructions.at(index).is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE))
				{
					if (!base)
					{
						base = instructions.at(index).get_base_type(0);
						break;
					}
					else if (instructions.at(index).is_operand_base(0, base))
						break;
				}
			}

			if (context.get_mnemonic(instructions.at(index).get_operand_data(1)) != UD_Inone)
				msg("[CodeDevirtualizer] EFLAGS mnemonic table corrupt with %08X.\n", context.get_mnemonic(instructions.at(index).get_operand_data(1)));
			else
			{
				static const ud_mnemonic_code eflags_mnemonics[] = { UD_Iclc, UD_Icld, UD_Icli, UD_Icmc, UD_Istc, UD_Istd, UD_Isti };
				context.set_mnemonic(instructions.at(index).get_operand_data<uint8_t>(1), eflags_mnemonics[i]);
			}
		}

		context.initialized_eflags_types = true;
	}

	return true;
}

bool wild_handler::perform_key_sequence(wild_context& context, uint32_t first_index, uint32_t last_index, uint32_t* data)
{
	std::size_t first = this->find_first_key_after(first_index);
	std::size_t last = this->find_last_key_before(last_index);

	if (first != static_cast<std::size_t>(-1) && last != static_cast<std::size_t>(-1))
	{
		for (std::size_t i = first; i <= last; i++)
		{
			if (!this->key_accessors.at(i).perform(context, data))
				return false;
		}

		return true;
	}
	
	return false;
}

bool wild_handler::step_handler(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	memset(context.step_params, 0, sizeof(context.step_params));

	switch (this->id)
	{
	case WILD_HANDLER_JUMP_INSIDE:
		return this->step_handler_jmp_inside(instructions, context, opcode);
		
	case WILD_HANDLER_JUMP_OUTSIDE_REGISTER:
		return this->step_handler_jmp_outside_register(instructions, context, opcode);
		
	case WILD_HANDLER_JUMP_OUTSIDE_MEMORY:
		return this->step_handler_jmp_outside_memory(instructions, context, opcode);
		
	case WILD_HANDLER_JUMP_OUTSIDE_IMMEDIATE:
		return this->step_handler_jmp_outside_immediate(instructions, context, opcode);

	case WILD_HANDLER_JCC_INSIDE:
		return this->step_handler_jcc_inside(instructions, context, opcode);
		
	case WILD_HANDLER_JCC_OUTSIDE:
		return this->step_handler_jcc_outside(instructions, context, opcode);
		
	case WILD_HANDLER_RET:
		return this->step_handler_ret(instructions, context, opcode);

	case WILD_HANDLER_UNDEF:
		return this->step_handler_undef(instructions, context, opcode);

	case WILD_HANDLER_LODSB:
	case WILD_HANDLER_LODSW:
	case WILD_HANDLER_LODSD:
		return this->step_handler_lods(instructions, context, opcode);
		
	case WILD_HANDLER_STOSB:
	case WILD_HANDLER_STOSW:
	case WILD_HANDLER_STOSD:
		return this->step_handler_stos(instructions, context, opcode);
		
	case WILD_HANDLER_SCASB:
	case WILD_HANDLER_SCASW:
	case WILD_HANDLER_SCASD:
		return this->step_handler_scas(instructions, context, opcode);
		
	case WILD_HANDLER_CMPSB:
	case WILD_HANDLER_CMPSW:
	case WILD_HANDLER_CMPSD:
		return this->step_handler_cmps(instructions, context, opcode);
		
	case WILD_HANDLER_MOVSB:
	case WILD_HANDLER_MOVSW:
	case WILD_HANDLER_MOVSD:
		return this->step_handler_movs(instructions, context, opcode);

	case WILD_HANDLER_PUSHFD:
		return this->step_handler_pushfd(instructions, context, opcode);

	case WILD_HANDLER_POPFD:
		return this->step_handler_popfd(instructions, context, opcode);
		
	case WILD_HANDLER_EFLAGS:
		return this->step_handler_eflags(instructions, context, opcode);

	case WILD_HANDLER_RESTORE_STACK:
		return this->step_handler_restore_stack(instructions, context, opcode);

	case WILD_HANDLER_LOAD_STACK:
		return this->step_handler_load_stack(instructions, context, opcode);
		
	case WILD_HANDLER_STORE_STACK:
		return this->step_handler_store_stack(instructions, context, opcode);
		
	case WILD_HANDLER_RESET_EFLAGS:
		return this->step_handler_reset_eflags(instructions, context, opcode);

	case WILD_HANDLER_RESET:
		return this->step_handler_reset(instructions, context, opcode);

	case WILD_HANDLER_CRYPT:
		return this->step_handler_crypt(instructions, context, opcode);

	default:
		break;
	}

	return this->step_handler_specific(instructions, context, opcode);
}

bool wild_handler::step_handler_jmp_inside(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t handler_index = opcode.read<uint16_t>(this->opcode_offsets[0]);
	uint32_t distance = opcode.read<uint32_t>(this->opcode_offsets[1]);
	
	context.step_params[0] = handler_index;
	context.step_params[1] = distance;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ijmp);
	instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);

	if (distance & 0x80000000)
	{
		instruction.set_operand_data(0, -static_cast<int32_t>(distance & 0x7FFFFFFF));
		context.create_label(context.current_virtual_opcode - (distance & 0x7FFFFFFF), handler_index);
	}
	else
	{
		instruction.set_operand_data(0, distance);
		context.create_label(context.current_virtual_opcode + distance, handler_index);
	}

	instructions.push_back(instruction);
	return true;
}

bool wild_handler::step_handler_jmp_outside_register(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t register_id = opcode.read<uint32_t>(this->opcode_offsets[0]);
	
	context.step_params[0] = register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ijmp);
	instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
	instruction.set_operand_base(0, context.get_vm_register(register_id));
	
	instructions.push_back(instruction);
	return true;
}

bool wild_handler::step_handler_jmp_outside_memory(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t register_id = opcode.read<uint32_t>(this->opcode_offsets[0]);
	
	context.step_params[0] = register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ijmp);
	instruction.set_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD);
	instruction.set_operand_base(0, context.get_vm_register(register_id));
	
	instructions.push_back(instruction);
	return true;
}

bool wild_handler::step_handler_jmp_outside_immediate(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t offset = opcode.read<uint32_t>(this->opcode_offsets[0]);
	
	context.step_params[2] = offset;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ijmp);
	instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);
	instruction.set_operand_data(0, context.vm_imagebase + offset);
	
	instructions.push_back(instruction);
	return true;
}

bool wild_handler::step_handler_jcc_inside(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t jcc_mnemonic_id = opcode.read<uint8_t>(this->opcode_offsets[0]);
	uint32_t handler_index = opcode.read<uint16_t>(this->opcode_offsets[1]);
	uint32_t distance = opcode.read<uint32_t>(this->opcode_offsets[2]);
	
	context.step_params[0] = jcc_mnemonic_id;
	context.step_params[1] = handler_index;
	context.step_params[2] = distance;
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(context.get_jcc_mnemonic(jcc_mnemonic_id));
	instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);
	
	if (distance & 0x80000000)
	{
		instruction.set_operand_data(0, -static_cast<int32_t>(distance & 0x7FFFFFFF));
		context.create_label(context.current_virtual_opcode - (distance & 0x7FFFFFFF), handler_index);
	}
	else
	{
		instruction.set_operand_data(0, distance);
		context.create_label(context.current_virtual_opcode + distance, handler_index);
	}
	
	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_jcc_outside(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t jcc_mnemonic_id = opcode.read<uint8_t>(this->opcode_offsets[0]);
	uint32_t offset = opcode.read<uint32_t>(this->opcode_offsets[1]);
	
	context.step_params[0] = jcc_mnemonic_id;
	context.step_params[1] = offset;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(context.get_jcc_mnemonic(jcc_mnemonic_id));
	instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);
	instruction.set_operand_data(0, context.vm_imagebase + offset);
	
	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_ret(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t arguments = opcode.read<uint32_t>(this->opcode_offsets[0]);
	
	context.step_params[0] = arguments;
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Iret);

	if (arguments)
	{
		instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_WORD);
		instruction.set_operand_data(0, arguments);
	}

	instructions.push_back(instruction);
	return true;
}

bool wild_handler::step_handler_undef(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t type = opcode.read<uint8_t>(this->opcode_offsets[0]);

	context.step_params[0] = UD_Iundef;
	context.step_params[1] = type;
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Iundef);

	instructions.push_back(instruction);
	
	/* Decode return address and create label */
	uint32_t return_address = context.vm_imagebase + opcode.read<uint32_t>(this->opcode_offsets[1]);
	
	if (!return_address)
		return false;

	ud_instruction return_instruction(return_address);
	return_instruction.set_input(context.to_segment(return_address));
	
	instruction_container return_instructions;
	
	for (std::size_t i = 0; i < 3; i++)
	{
		if (!return_instructions.decode_assembly(return_instruction))
			return false;

		if (i == 0)
			instructions.back().set_index(return_address);
		else
		{
			if (return_instruction.is_mnemonic_not(UD_Ipush) ||
				return_instruction.is_operand_type_not(0, UD_OP_IMM, UD_SIZE_DWORD))
			{
				return false;
			}
		}
	}
	
	context.create_label(context.vm_imagebase + return_instructions.at(1).get_operand_data(0), return_instructions.at(2).get_operand_data(0));
	return true;
}

bool wild_handler::step_handler_lods(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	static const ud_mnemonic_code mnemonics[] = { UD_Ilodsb, UD_Ilodsw, UD_Ilodsd };
	
	this->step_opcode_regions(context, opcode);

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(mnemonics[this->id - WILD_HANDLER_LODSB]);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_stos(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	static const ud_mnemonic_code mnemonics[] = { UD_Istosb, UD_Istosw, UD_Istosd };
	
	this->step_opcode_regions(context, opcode);
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(mnemonics[this->id - WILD_HANDLER_STOSB]);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_scas(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	static const ud_mnemonic_code mnemonics[] = { UD_Iscasb, UD_Iscasw, UD_Iscasd };
	
	this->step_opcode_regions(context, opcode);

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(mnemonics[this->id - WILD_HANDLER_SCASB]);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_cmps(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	static const ud_mnemonic_code mnemonics[] = { UD_Icmpsb, UD_Icmpsw, UD_Icmpsd };
	
	this->step_opcode_regions(context, opcode);

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(mnemonics[this->id - WILD_HANDLER_CMPSB]);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_movs(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	static const ud_mnemonic_code mnemonics[] = { UD_Imovsb, UD_Imovsw, UD_Imovsd };
	
	this->step_opcode_regions(context, opcode);
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(mnemonics[this->id - WILD_HANDLER_MOVSB]);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}
	
bool wild_handler::step_handler_pushfd(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	this->step_opcode_regions(context, opcode);
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ipushfd);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_popfd(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	this->step_opcode_regions(context, opcode);
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ipopfd);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}
	
bool wild_handler::step_handler_eflags(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t mnemonic_id = opcode.read<uint8_t>(this->opcode_offsets[1]);

	context.step_params[0] = mnemonic_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(context.get_mnemonic(mnemonic_id));

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_restore_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t value = opcode.read<uint8_t>(this->opcode_offsets[0]);

	context.step_params[0] = UD_Irestorestack;
	context.step_params[1] = value;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Irestorestack);
	instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);
	instruction.set_operand_data(0, value);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_load_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t esp_register_id = opcode.read<uint16_t>(this->opcode_offsets[0]);

	context.step_params[0] = UD_Iloadstack;
	context.step_params[1] = esp_register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Iloadstack);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_handler_store_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t esp_register_id = opcode.read<uint16_t>(this->opcode_offsets[0]);
	context.set_vm_register(esp_register_id, UD_R_ESP);

	context.step_params[0] = UD_Istorestack;
	context.step_params[1] = esp_register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Istorestack);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), true);
}
	
bool wild_handler::step_handler_reset_eflags(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	context.step_params[0] = UD_Ireseteflags;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ireseteflags);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(0), true);
}

bool wild_handler::step_handler_reset(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	context.reset_key_data();

	context.step_params[0] = UD_Ireset;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ireset);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(0), true);
}
	
bool wild_handler::step_handler_crypt(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t register_id = opcode.read<uint16_t>(this->opcode_offsets[0]);
	uint32_t value = this->opcode_offsets[1];

	context.step_params[0] = UD_Icrypt;
	context.step_params[1] = register_id;
	context.step_params[2] = value;

	if (!get_many_bytes(context.vm_context + value, &value, sizeof(uint32_t)))
		return false;

	context.step_params[3] = value;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Icrypt);
	instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
	instruction.set_operand_base(0, context.get_vm_register(register_id));
	instruction.set_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD);
	instruction.set_operand_data(1, value);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool wild_handler::step_opcode_regions(wild_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->opcode_regions.empty())
	{
		this->perform_key_sequence(context, 0, this->flow_data_index, &key_data);
	}
	else
	{
		if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < this->opcode_regions.at(0).index_start)
			this->perform_key_sequence(context, 0, this->opcode_regions.at(0).index_start - 1, &key_data);

		for (std::size_t i = 0; i < this->opcode_regions.size(); i++)
		{
			key_data = 0;

			switch (this->opcode_regions.at(i).opcode_size)
			{
			case UD_SIZE_BYTE:
				key_data = opcode.read<uint8_t>(this->opcode_regions.at(i).opcode_offset);
				break;

			case UD_SIZE_WORD:
				key_data = opcode.read<uint16_t>(this->opcode_regions.at(i).opcode_offset);
				break;

			case UD_SIZE_DWORD:
				key_data = opcode.read<uint32_t>(this->opcode_regions.at(i).opcode_offset);
				break;

			default:
				break;
			}
			
			uint32_t index_end = 0;

			if ((i + 1) < this->opcode_regions.size())
				index_end = this->opcode_regions.at(i + 1).index_start;
			else
				index_end = this->flow_read_index;

			this->perform_key_sequence(context, this->opcode_regions.at(i).index_start, index_end - 1, &key_data);
		}
	}

	return true;
}

bool wild_handler::step_handler_flow(wild_context& context, uint16_t raw_handler_offset, bool skip_flow_mutation)
{
	if (skip_flow_mutation)
	{
		context.current_handler_offset = raw_handler_offset;
		context.current_virtual_opcode += this->opcode_size;
	}
	else
	{
		uint32_t handler_offset = raw_handler_offset;

		if (this->opcode_size == OPCODE_SIZE_SUB || this->opcode_size == OPCODE_SIZE_RETN || this->opcode_size == OPCODE_SIZE_INVALID)
			return false;

		if (this->flow_key_indexes.empty())
		{
			if (this->flow_mutation_index)
				instruction::emulate(static_cast<ud_mnemonic_code>(this->flow_mutation_mnemonic), UD_SIZE_DWORD, this->flow_mutation_constant, &handler_offset);
		}
		else
		{
			std::size_t first = this->find_first_key_after(this->flow_key_indexes.front());
			std::size_t last = this->find_last_key_before(this->flow_key_indexes.back());
			
			if (first == static_cast<std::size_t>(-1) || last == static_cast<std::size_t>(-1))
				return false;

			bool flow_mutated = false;
				
			for (std::size_t i = first; i <= last; i++)
			{
				if (this->flow_mutation_index && !flow_mutated && this->key_accessors.at(i).index > this->flow_mutation_index)
				{
					instruction::emulate(static_cast<ud_mnemonic_code>(this->flow_mutation_mnemonic), UD_SIZE_DWORD, this->flow_mutation_constant, &handler_offset);
					flow_mutated = true;
				}
				
				if (!this->key_accessors.at(i).perform(context, &handler_offset))
					return false;
			}

			if (this->flow_mutation_index && !flow_mutated)
				instruction::emulate(static_cast<ud_mnemonic_code>(this->flow_mutation_mnemonic), UD_SIZE_DWORD, this->flow_mutation_constant, &handler_offset);
		}
		
		context.current_handler_offset = handler_offset;
		context.current_virtual_opcode += this->opcode_size;
	}

	return true;
}