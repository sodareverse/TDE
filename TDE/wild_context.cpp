#include "wild_context.hpp"

#include "instruction_emulator.hpp"

#include <idp.hpp>
#include <allins.hpp>

void wild_context::clear()
{
	this->initialized_crypto_offset = false;
	this->crypto_offset = 0;

	this->initialized_jcc_types = false;
	this->initialized_eflags_types = false;

	this->current_register_type = 0;
	
	this->register_addr1_id = 0xFFFF;
	this->register_addr2_id = 0xFFFF;

	this->register_types.clear();
	this->mnemonic_types.clear();
	this->jcc_mnemonic_types.clear();
}

void wild_context::set_initial_parameters(uint32_t virtual_opcode, uint32_t handler_offset)
{
	this->initial_virtual_opcode = virtual_opcode;
	this->current_virtual_opcode = this->initial_virtual_opcode;
	
	this->initial_handler_offset = handler_offset;
	this->current_handler_offset = this->initial_handler_offset;
}
	
void wild_context::prepare_initial_parameters()
{
	this->initial_virtual_opcode += this->vm_imagebase;
	this->current_virtual_opcode += this->vm_imagebase;
}

bool wild_context::is_key_access_instruction(ud_instruction& instruction, bool allow_mov)
{
	if (instruction.compare_mnemonic(allow_mov, false, true))
	{
		/* 0: ___ unknown ptr [ebp+xx],___ */
		if (instruction.is_operand_type(0, UD_OP_MEM) &&
			instruction.is_operand_base(0, UD_R_EBP) &&
			instruction.has_operand_index_not(0) &&
			instruction.has_operand_scale_not(0))
		{
			if (this->get_key(instruction.get_operand_data(0), nullptr))
				return true;
		}
		/* 0: ___ ___,unknown ptr [ebp+xx] */
		else if (instruction.is_operand_type(1, UD_OP_MEM) &&
			instruction.is_operand_base(1, UD_R_EBP) &&
			instruction.has_operand_index_not(1) &&
			instruction.has_operand_scale_not(1))
		{
			if (this->get_key(instruction.get_operand_data(1), nullptr))
				return true;
		}
	}

	return false;
}
	
bool wild_context::is_opcode_access_instruction(ud_instruction& instruction)
{
	/* 0: ___ dword ptr [ebp+xx] */
	if (instruction.is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
		instruction.is_operand_base(0, UD_R_EBP) &&
		instruction.has_operand_index_not(0) &&
		instruction.has_operand_scale_not(0) &&
		instruction.is_operand_data(0, this->vm_opcode_offset))
	{
		return true;
	}
	/* 0: ___ ___,dword ptr [ebp+xx] */
	else if (instruction.is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
		instruction.is_operand_base(1, UD_R_EBP) &&
		instruction.has_operand_index_not(1) &&
		instruction.has_operand_scale_not(1) &&
		instruction.is_operand_data(1, this->vm_opcode_offset))
	{
		/* 0: ___ reg,dword ptr [ebp+xx] */
		return instruction.is_operand_type(0, UD_OP_REG);
	}

	return false;
}

ud_type wild_context::get_vm_register(uint16_t id)
{
	std::map<uint16_t, ud_type>::const_iterator iter = this->register_types.find(id);

	if (iter != this->register_types.end())
		return iter->second;
	else
		return UD_NONE;
}
	
ud_type wild_context::get_vm_high_byte_register(uint16_t id)
{
	return static_cast<ud_type>(this->get_vm_register(id - 1) + (UD_R_AH - UD_R_AL));
}

bool wild_context::set_vm_register(uint16_t id, ud_type type)
{
	if (this->register_types.count(id) != 0)
		return false;

	this->register_types[id] = type;
	return true;
}

ud_mnemonic_code wild_context::get_mnemonic(uint8_t id)
{
	std::map<uint8_t, ud_mnemonic_code>::const_iterator iter = this->mnemonic_types.find(id);

	if (iter != this->mnemonic_types.end())
		return iter->second;
	else
		return UD_Inone;
}

bool wild_context::set_mnemonic(uint8_t id, ud_mnemonic_code mnemonic)
{
	if (this->mnemonic_types.count(id) != 0)
		return false;

	this->mnemonic_types[id] = mnemonic;
	return true;
}

ud_mnemonic_code wild_context::get_jcc_mnemonic(uint8_t id)
{
	std::map<uint8_t, ud_mnemonic_code>::const_iterator iter = this->jcc_mnemonic_types.find(id);

	if (iter != this->jcc_mnemonic_types.end())
		return iter->second;
	else
		return UD_Inone;
}

bool wild_context::set_jcc_mnemonic(uint8_t id, ud_mnemonic_code mnemonic)
{
	if (this->jcc_mnemonic_types.count(id) != 0)
		return false;

	this->jcc_mnemonic_types[id] = mnemonic;
	return true;
}

bool wild_context::decode_zero_data(uint32_t vm_entrance)
{
	ud_instruction instruction(vm_entrance);
	instruction.set_input(this->to_segment(vm_entrance));
	
	instruction_container instructions;
		
	do
	{
		if (!instructions.decode_assembly(instruction))
			return false;
	}
	while (instruction.is_mnemonic_not(UD_Ijmp) || instruction.is_operand_type_not(0, UD_OP_MEM));

	return this->parse_zero_data(instructions);
}

bool wild_context::parse_zero_data(instruction_container& instructions)
{
	std::size_t index = 0;

	return (this->parse_image_base(instructions, index) &&
		this->parse_vm_context(instructions, index) &&
		this->parse_vm_imagebase_offset(instructions, index) &&
		this->parse_vm_imagebase_preferred_offset(instructions, index) &&
		this->parse_vm_imagebase_preferred(instructions, index) &&
		this->parse_vm_opcode_offset(instructions, index) &&
		this->parse_vm_handler_table(instructions, index) &&
		this->parse_vm_handler_table_offset(instructions, index) &&
		this->parse_vm_handler_count(instructions, index));
}
	
bool wild_context::parse_image_base(instruction_container& instructions, std::size_t& index)
{
	this->vm_imagebase = 0;

	for (std::size_t i = index, stage = 0; i < instructions.size(); i++)
	{
		/* 0: call $+5 */
		if (instructions.at(i).is_mnemonic(UD_Icall) &&
			instructions.at(i).is_operand_type(0, UD_OP_JIMM) &&
			instructions.at(i).is_operand_data(0, 0))
		{
			this->vm_imagebase = instructions.at(i).get_address_next<uint32_t>();
			stage++;
		}
		/* 0: ___ ecx,imm */
		else if (stage == 1 &&
			instructions.at(i).compare_mnemonic(false, false, true) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(0, UD_R_ECX) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM))
		{
			instruction::emulate(instructions.at(i).get_mnemonic(), instructions.at(i).get_base_size(0), instructions.at(i).get_operand_data<uint32_t>(1), &this->vm_imagebase);
			stage++;
		}
		/* 0: ___ ecx,imm32 */
		else if (stage == 2 &&
			instructions.at(i).compare_mnemonic(false, false, true) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(0, UD_R_ECX) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
		{
			instruction::emulate(instructions.at(i).get_mnemonic(), instructions.at(i).get_base_size(0), instructions.at(i).get_operand_data<uint32_t>(1), &this->vm_imagebase);
			stage++;
		}
		/* 0: mov ebp,imm32 */
		else if (stage == 3 &&
			instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(0, UD_R_EBP) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
		{
			index = i;
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Ipush))
			break;
	}

	return false;
}

bool wild_context::parse_vm_context(instruction_container& instructions, std::size_t& index)
{
	this->vm_context = 0;

	for (std::size_t i = index, stage = 0, context_offset = 0; i < instructions.size(); i++)
	{
		/* 0: mov ebp,imm32 */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(0, UD_R_EBP) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
		{
			context_offset = instructions.at(i).get_operand_data<uint32_t>(1);
			stage++;
		}
		/* 0: ___ ebp,ecx */
		else if (stage == 1 &&
			instructions.at(i).compare_mnemonic(false, false, true) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(0, UD_R_EBP) &&
			instructions.at(i).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(1, UD_R_ECX))
		{
			index = i + 1;
			this->vm_context = this->vm_imagebase + context_offset;
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Ipush))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_imagebase_offset(instruction_container& instructions, std::size_t& index)
{
	this->vm_imagebase_offset = 0;

	if (instructions.find_mnemonic_index(UD_Ipop, index))
	{
		for (std::size_t i = index; i < instructions.size(); i++)
		{
			/*
				0: mov reg,imm32
				1: mov dword ptr [reg+reg],reg
			*/
			if (instructions.at(i).is_mnemonic(UD_Imov) &&
				instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
				instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&

				instructions.at(i + 1).is_mnemonic(UD_Imov) &&
				instructions.at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
				(instructions.at(i + 1).is_operand_base(0, instructions.at(i), 0) ||
				instructions.at(i + 1).is_operand_index_by_base(0, instructions.at(i), 0)) &&
				instructions.at(i + 1).is_operand_type(1, UD_OP_REG, UD_SIZE_DWORD))
			{
				index = i + 2;
				this->vm_imagebase_offset = instructions.at(i).get_operand_data<uint32_t>(1);
				return true;
			}
			else if (instructions.at(i).is_mnemonic(UD_Icmp))
				break;
		}
	}

	return false;
}

bool wild_context::parse_vm_imagebase_preferred_offset(instruction_container& instructions, std::size_t& index)
{
	this->vm_imagebase_preferred_offset = 0;

	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/*
			0: mov reg,imm32
			1: mov dword ptr [reg+reg],imm32
		*/
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&

			instructions.at(i + 1).is_mnemonic(UD_Imov) &&
			instructions.at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(i + 1).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&
			(instructions.at(i + 1).is_operand_base(0, instructions.at(i), 0) ||
			instructions.at(i + 1).is_operand_index_by_base(0, instructions.at(i), 0)))
		{
			index = i + 1;
			this->vm_imagebase_preferred_offset = instructions.at(i).get_operand_data<uint32_t>(1);
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Icmp))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_imagebase_preferred(instruction_container& instructions, std::size_t& index)
{
	this->vm_imagebase_preferred = 0;

	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/* 0: mov dword ptr [reg+reg],imm32 */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(i).has_operand_base(0) &&
			instructions.at(i).has_operand_index(0) &&
			instructions.at(i).has_operand_scale_not(0) &&
			instructions.at(i).has_operand_data_not(0) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
		{
			index = i + 1;
			this->vm_imagebase_preferred = instructions.at(i).get_operand_data<uint32_t>(1);
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Icmp))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_opcode_offset(instruction_container& instructions, std::size_t& index)
{
	this->vm_opcode_offset = 0;

	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/*
			0: mov reg,imm32
			1: mov reg,dword ptr [esp+28]
		*/
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&

			instructions.at(i + 1).is_mnemonic(UD_Imov) &&
			instructions.at(i + 1).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i + 1).is_operand_base_not(0, UD_R_ESP) &&
			instructions.at(i + 1).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(i + 1).is_operand_base(1, UD_R_ESP) &&
			instructions.at(i + 1).has_operand_index_not(1) &&
			instructions.at(i + 1).has_operand_scale_not(1) &&
			instructions.at(i + 1).is_operand_data(1, 0x28))
		{
			index = i + 1;
			this->vm_opcode_offset = instructions.at(i).get_operand_data<uint32_t>(1);
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Icmp))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_handler_table(instruction_container& instructions, std::size_t& index)
{
	this->vm_handler_table = 0;

	for (std::size_t i = index, stage = 0; i < instructions.size(); i++)
	{
		/* 0: mov reg,dword ptr [esp+28] */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base_not(0, UD_R_ESP) &&
			instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base(1, UD_R_ESP) &&
			instructions.at(i).has_operand_index_not(1) &&
			instructions.at(i).has_operand_scale_not(1) &&
			instructions.at(i).is_operand_data(1, 0x28))
		{
			stage++;
		}
		/* 0: mov reg,imm32 */
		else if (stage == 1 &&
			instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_base_not(0, UD_R_ESP) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&
			instructions.at(i).has_operand_data(1))
		{
			index = i + 1;
			this->vm_handler_table = this->vm_imagebase + instructions.at(i).get_operand_data<uint32_t>(1);
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Icmp))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_handler_table_offset(instruction_container& instructions, std::size_t& index)
{
	this->vm_handler_table_offset = 0;

	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/* 
			0: mov reg,imm32
			1: mov reg,dword ptr [reg+reg]
		*/
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD) &&

			instructions.at(i + 1).is_mnemonic(UD_Imov) &&
			instructions.at(i + 1).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			instructions.at(i + 1).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			(instructions.at(i + 1).is_operand_base(1, instructions.at(i), 0) ||
			instructions.at(i + 1).is_operand_index_by_base(1, instructions.at(i), 0)))
		{
			index = i + 1;
			this->vm_handler_table_offset = instructions.at(i).get_operand_data<uint32_t>(1);
			return true;
		}
		else if (instructions.at(i).is_mnemonic(UD_Icmp))
			break;
	}
	
	return false;
}

bool wild_context::parse_vm_handler_count(instruction_container& instructions, std::size_t& index)
{
	this->vm_handler_count = 0;
	
	if (instructions.find_mnemonic_index(UD_Ipush, index))
	{
		for (std::size_t i = index; i < instructions.size(); i++)
		{
			/*
				0: push reg
				1: mov reg,imm32
			*/
			if (instructions.at(i).is_mnemonic(UD_Ipush) &&
				instructions.at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&

				instructions.at(i + 1).is_mnemonic(UD_Imov) &&
				instructions.at(i + 1).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
				instructions.at(i + 1).is_operand_base(0, instructions.at(i), 0) &&
				instructions.at(i + 1).is_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD))
			{
				this->vm_handler_count = (instructions.at(i + 1).get_operand_data<uint32_t>(1) >> 2);
				return true;
			}
			else if (instructions.at(i).is_mnemonic(UD_Ipush))
				break;
		}
	}

	return false;
}