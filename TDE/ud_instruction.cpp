#include "ud_instruction.hpp"

#include <algorithm>

void ud_instruction::initialize(uint64_t base_address, uint8_t mode)
{
	this->index = 0;
	this->key_data = 0;

	ud_init(this);
	ud_set_pc(this, base_address);
	ud_set_mode(this, mode);
	ud_set_syntax(this, UD_SYN_INTEL);

	this->opr_mode = mode;
	this->insn_offset = this->pc;
}

ud_instruction::ud_instruction()
{
	this->initialize(0);
}

ud_instruction::ud_instruction(uint64_t base_address)
{
	this->initialize(base_address);
}
uint32_t ud_instruction::get_index()
{
	return this->index;
}

void ud_instruction::set_index(uint32_t index)
{
	this->index = index;
}

uint32_t ud_instruction::get_key_data()
{
	return this->key_data;
}

void ud_instruction::set_key_data(uint32_t key_data)
{
	this->key_data = key_data;
}

void ud_instruction::set_input(uint8_t* address, uint32_t size)
{
	ud_set_input_buffer(this, address, size);
}

void ud_instruction::set_input(std::pair<uint8_t*, uint32_t> input)
{
	this->set_input(input.first, input.second);
}

void ud_instruction::skip_input(uint32_t length)
{
	this->inp_buf_index += length;
	this->pc += length;
}

void ud_instruction::reset_input(uint32_t address)
{
	uint32_t base_address = static_cast<uint32_t>(this->pc - this->inp_buf_index);
	uint32_t base_offset = (address - base_address);

	this->inp_buf_index = base_offset;
	this->pc = base_address + base_offset;
}

void ud_instruction::set_program_counter(uint64_t counter)
{
	ud_set_pc(this, counter);
}

template <typename T>
T ud_instruction::get_operand_data(std::size_t index) const
{
	return static_cast<T>(this->get_operand_data<uint64_t>(index));
}

template <>
int8_t ud_instruction::get_operand_data<int8_t>(std::size_t index) const
{
	return this->operand[index].lval.sbyte;
}

template <>
uint8_t ud_instruction::get_operand_data<uint8_t>(std::size_t index) const
{
	return this->operand[index].lval.ubyte;
}

template <>
int16_t ud_instruction::get_operand_data<int16_t>(std::size_t index) const
{
	return this->operand[index].lval.sword;
}

template <>
uint16_t ud_instruction::get_operand_data<uint16_t>(std::size_t index) const
{
	return this->operand[index].lval.uword;
}

template <>
int32_t ud_instruction::get_operand_data<int32_t>(std::size_t index) const
{
	return this->operand[index].lval.sdword;
}

template <>
uint32_t ud_instruction::get_operand_data<uint32_t>(std::size_t index) const
{
	return this->operand[index].lval.udword;
}

template <>
int64_t ud_instruction::get_operand_data<int64_t>(std::size_t index) const
{
	return this->operand[index].lval.sqword;
}

template <>
uint64_t ud_instruction::get_operand_data<uint64_t>(std::size_t index) const
{
	return this->operand[index].lval.uqword;
}

template <>
void ud_instruction::set_operand_data<int8_t>(std::size_t index, int8_t data)
{
	this->operand[index].lval.sbyte = data;
}

template <>
void ud_instruction::set_operand_data<uint8_t>(std::size_t index, uint8_t data)
{
	this->operand[index].lval.ubyte = data;
}
	
template <>
void ud_instruction::set_operand_data<int16_t>(std::size_t index, int16_t data)
{
	this->operand[index].lval.sword = data;
}

template <>
void ud_instruction::set_operand_data<uint16_t>(std::size_t index, uint16_t data)
{
	this->operand[index].lval.uword = data;
}
	
template <>
void ud_instruction::set_operand_data<int32_t>(std::size_t index, int32_t data)
{
	this->operand[index].lval.sdword = data;
}

template <>
void ud_instruction::set_operand_data<uint32_t>(std::size_t index, uint32_t data)
{
	this->operand[index].lval.udword = data;
}

template <>
void ud_instruction::set_operand_data<int64_t>(std::size_t index, int64_t data)
{
	this->operand[index].lval.sqword = data;
}

template <>
void ud_instruction::set_operand_data<uint64_t>(std::size_t index, uint64_t data)
{
	this->operand[index].lval.uqword = data;
}
	
ud_mnemonic_code ud_instruction::get_mnemonic() const
{
	return this->mnemonic;	
}

ud_type ud_instruction::get_operand_type(std::size_t index) const
{
	return this->operand[index].type;
}

ud_size ud_instruction::get_operand_size(std::size_t index) const
{
	return static_cast<ud_size>(this->operand[index].size);
}

ud_type ud_instruction::get_base_type(std::size_t index) const
{
	return this->operand[index].base;
}

ud_type ud_instruction::get_base_high_type(std::size_t index) const
{
	switch (this->operand[index].base)
	{
	case UD_R_AL:	case UD_R_AH:	case UD_R_AX:	case UD_R_EAX:	case UD_R_RAX:
		return UD_R_AH;
		
	case UD_R_CL:	case UD_R_CH:	case UD_R_CX:	case UD_R_ECX:	case UD_R_RCX:
		return UD_R_CH;
		
	case UD_R_DL:	case UD_R_DH:	case UD_R_DX:	case UD_R_EDX:	case UD_R_RDX:
		return UD_R_DH;
		
	case UD_R_BL:	case UD_R_BH:	case UD_R_BX:	case UD_R_EBX:	case UD_R_RBX:
		return UD_R_BH;

	default:
		break;
	}

	return UD_NONE;
}

ud_type ud_instruction::get_base_size_type(std::size_t index, ud_size size) const
{
	return this->base_to_size_type(this->operand[index].base, size);
}

ud_size ud_instruction::get_base_size(std::size_t index) const
{
	switch (this->operand[index].type)
	{
	case UD_OP_REG:
	case UD_OP_CONST:
		return static_cast<ud_size>(this->operand[index].size);

	case UD_OP_MEM:
		return this->get_type_size(this->operand[index].base);

	default:
		break;
	}

	return UD_SIZE_NONE;
}

ud_size ud_instruction::get_type_size(ud_type type) const
{
	if (type >= UD_R_AL && type <= UD_R_R15B)
		return UD_SIZE_BYTE;
	else if (type >= UD_R_AX && type <= UD_R_R15W)
		return UD_SIZE_WORD;
	else if (type >= UD_R_EAX && type <= UD_R_R15D)
		return UD_SIZE_DWORD;
	else if (type >= UD_R_RAX && type <= UD_R_R15)
		return UD_SIZE_QWORD;
	else 
		return UD_SIZE_NONE;
}

ud_type ud_instruction::base_to_size_type(ud_type base, ud_size size) const
{
	static const ud_type accumulator_types[]		= { UD_R_AL,  UD_R_AX, UD_R_EAX, UD_R_RAX };
	static const ud_type counter_types[]			= { UD_R_CL,  UD_R_CX, UD_R_ECX, UD_R_RCX };
	static const ud_type data_types[]				= { UD_R_DL,  UD_R_DX, UD_R_EDX, UD_R_RDX };
	static const ud_type base_types[]				= { UD_R_BL,  UD_R_BX, UD_R_EBX, UD_R_RBX };
	static const ud_type stack_pointer_types[]		= { UD_R_SPL, UD_R_SP, UD_R_ESP, UD_R_RSP };
	static const ud_type stack_base_types[]			= { UD_R_BPL, UD_R_BP, UD_R_EBP, UD_R_RBP };
	static const ud_type source_index_types[]		= { UD_R_SIL, UD_R_SI, UD_R_ESI, UD_R_RSI };
	static const ud_type destination_index_types[]	= { UD_R_DIL, UD_R_DI, UD_R_EDI, UD_R_RDI };
	
	/*
		x = std::pow(y, z) is reversible through z = log(x) / log(y).

		std::pow(2, 3) = 8		-> log(8)  / log(2) = 3
		std::pow(2, 4) = 16		-> log(16) / log(2) = 4
		std::pow(2, 5) = 32		-> log(32) / log(2) = 5
		std::pow(2, 6) = 64		-> log(32) / log(2) = 6
	*/

	const uint8_t logarithm = static_cast<uint8_t>(std::log(static_cast<uint16_t>(size)) / std::log(2)) - 3;

	switch (base)
	{
	case UD_R_AL:	case UD_R_AH:	case UD_R_AX:	case UD_R_EAX:	case UD_R_RAX:
		return accumulator_types[logarithm];

	case UD_R_CL:	case UD_R_CH:	case UD_R_CX:	case UD_R_ECX:	case UD_R_RCX:
		return counter_types[logarithm];

	case UD_R_DL:	case UD_R_DH:	case UD_R_DX:	case UD_R_EDX:	case UD_R_RDX:
		return data_types[logarithm];
		
	case UD_R_BL:	case UD_R_BH:	case UD_R_BX:	case UD_R_EBX:	case UD_R_RBX:
		return base_types[logarithm];

	case UD_R_SPL:					case UD_R_SP:	case UD_R_ESP:	case UD_R_RSP:
		return stack_pointer_types[logarithm];

	case UD_R_BPL:					case UD_R_BP:	case UD_R_EBP:	case UD_R_RBP: 
		return stack_base_types[logarithm];
		
	case UD_R_SIL:					case UD_R_SI:	case UD_R_ESI:	case UD_R_RSI:
		return source_index_types[logarithm];

	case UD_R_DIL:					case UD_R_DI:	case UD_R_EDI:	case UD_R_RDI:
		return destination_index_types[logarithm];
  
	case UD_R_ADDR1:
		return UD_R_ADDR1;

	case UD_R_ADDR2:
		return UD_R_ADDR2;

	default:
		break;
	}

	return UD_NONE;
}

uint32_t ud_instruction::get_params(uint32_t operand) const
{
	switch (this->operand[operand].type)
	{
	case UD_OP_REG:
		return this->get_base_type(operand);

	case UD_OP_IMM:
		return this->get_operand_data(operand);

	default:
		break;
	}

	return 0;
}

uint16_t ud_instruction::get_loword(uint32_t operand) const
{
	switch (this->operand[operand].type)
	{
	case UD_OP_REG:
		return this->get_base_type(operand);
		
	case UD_OP_IMM:
		return this->get_operand_data<uint16_t>(operand);

	case UD_OP_MEM:
		return (this->get_base_type(operand) << 8);

	default:
		break;
	}

	return 0;
}

bool ud_instruction::is_mnemonic(ud_mnemonic_code mnemonic) const
{
	return (this->mnemonic == mnemonic);
}

bool ud_instruction::is_mnemonic(std::initializer_list<ud_mnemonic_code> mnemonics) const
{
	for (std::initializer_list<ud_mnemonic_code>::const_iterator iter = mnemonics.begin(); iter != mnemonics.end(); iter++)
	{
		if (this->is_mnemonic(*iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_mnemonic_not(ud_mnemonic_code mnemonic) const
{
	return (!this->is_mnemonic(mnemonic));
}

bool ud_instruction::is_mnemonic_not(std::initializer_list<ud_mnemonic_code> mnemonics) const
{
	return (!this->is_mnemonic(mnemonics));
}

bool ud_instruction::is_mnemonic_jcc() const
{
	return this->is_mnemonic({ UD_Ija, UD_Ijae, UD_Ijb, UD_Ijbe, UD_Ijz, UD_Ijnz, UD_Ijg, UD_Ijge, UD_Ijl, UD_Ijle, UD_Ijo, UD_Ijno, UD_Ijp, UD_Ijnp, UD_Ijs, UD_Ijns, UD_Ijcxz, UD_Ijecxz, UD_Ijrcxz });
}

bool ud_instruction::is_mnemonic_jcc_not() const
{
	return (!this->is_mnemonic_jcc());
}

bool ud_instruction::is_operand_null(std::size_t index) const
{
	return (this->operand[index].type == UD_NONE);
}

bool ud_instruction::is_operand_not_null(std::size_t index) const
{
	return (!this->is_operand_null(index));
}

bool ud_instruction::is_operand_type(std::size_t index, ud_type type, ud_size size) const
{
	return (this->operand[index].type == type && (size == UD_SIZE_NONE || this->operand[index].size == size));
}

bool ud_instruction::is_operand_type(std::size_t index, std::initializer_list<ud_type> types) const
{
	for (std::initializer_list<ud_type>::const_iterator iter = types.begin(); iter != types.end(); iter++)
	{
		if (this->is_operand_type(index, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_type(std::size_t index, ud_type type, std::initializer_list<ud_size> sizes) const
{
	for (std::initializer_list<ud_size>::const_iterator iter = sizes.begin(); iter != sizes.end(); iter++)
	{
		if (this->is_operand_type(index, type, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_type(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return this->is_operand_type(index, instruction.operand[instruction_index].type, static_cast<ud_size>(instruction.operand[instruction_index].size));
}

bool ud_instruction::is_operand_type_not(std::size_t index, ud_type type, ud_size size) const
{
	return (!this->is_operand_type(index, type, size));
}

bool ud_instruction::is_operand_type_not(std::size_t index, std::initializer_list<ud_type> types) const
{
	return (!this->is_operand_type(index, types));
}

bool ud_instruction::is_operand_type_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_type(index, instruction, instruction_index));
}

bool ud_instruction::is_operand_size(std::size_t index, ud_size size) const
{
	return (this->operand[index].size == size);
}

bool ud_instruction::is_operand_size_not(std::size_t index, ud_size size) const
{
	return (!this->is_operand_size(index, size));
}

bool ud_instruction::is_operand_sib(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (this->is_operand_base(index, instruction, instruction_index) &&
		this->is_operand_index(index, instruction, instruction_index) &&
		this->is_operand_scale(index, instruction, instruction_index));
}

bool ud_instruction::has_operand_base(std::size_t index) const
{
	return (this->operand[index].base != UD_NONE);
}

bool ud_instruction::has_operand_base_not(std::size_t index) const
{
	return (!this->has_operand_base(index));
}

bool ud_instruction::is_operand_base(std::size_t index, ud_type type) const
{
	return (this->operand[index].base == type);
}

bool ud_instruction::is_operand_base(std::size_t index, std::initializer_list<ud_type> types) const
{
	for (std::initializer_list<ud_type>::const_iterator iter = types.begin(); iter != types.end(); iter++)
	{
		if (this->is_operand_base(index, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (this->is_operand_base(index, instruction.operand[instruction_index].base));
}

bool ud_instruction::is_operand_base_not(std::size_t index, ud_type type) const
{
	return (!this->is_operand_base(index, type));
}

bool ud_instruction::is_operand_base_not(std::size_t index, std::initializer_list<ud_type> types) const
{
	return (!this->is_operand_base(index, types));
}

bool ud_instruction::is_operand_base_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_base(index, instruction, instruction_index));
}

bool ud_instruction::is_operand_base_size(std::size_t index, ud_size size) const
{
	return (this->get_base_size(index) == size);
}

bool ud_instruction::is_operand_base_size_not(std::size_t index, ud_size size) const
{
	return (!this->is_operand_base_size(index, size));
}

bool ud_instruction::is_operand_base_family(std::size_t index, ud_type family) const
{
	switch (family)
	{
	case UD_R_AL:	case UD_R_AH:	case UD_R_AX:	case UD_R_EAX:	case UD_R_RAX:
		return this->is_operand_base(index, { UD_R_AL, UD_R_AH, UD_R_AX, UD_R_EAX, UD_R_RAX });

	case UD_R_CL:	case UD_R_CH:	case UD_R_CX:	case UD_R_ECX:	case UD_R_RCX:
		return this->is_operand_base(index, { UD_R_CL, UD_R_CH, UD_R_CX, UD_R_ECX, UD_R_RCX });

	case UD_R_DL:	case UD_R_DH:	case UD_R_DX:	case UD_R_EDX:	case UD_R_RDX:
		return this->is_operand_base(index, { UD_R_DL, UD_R_DH, UD_R_DX, UD_R_EDX, UD_R_RDX });
		
	case UD_R_BL:	case UD_R_BH:	case UD_R_BX:	case UD_R_EBX:	case UD_R_RBX:
		return this->is_operand_base(index, { UD_R_BL, UD_R_BH, UD_R_BX, UD_R_EBX, UD_R_RBX });
		
	case UD_R_SPL:					case UD_R_SP:	case UD_R_ESP:	case UD_R_RSP:
		return this->is_operand_base(index, { UD_R_SPL, UD_R_SP, UD_R_ESP, UD_R_RSP });

	case UD_R_BPL:					case UD_R_BP:	case UD_R_EBP:	case UD_R_RBP: 
		return this->is_operand_base(index, { UD_R_BPL, UD_R_BP, UD_R_EBP, UD_R_RBP });
		
	case UD_R_SIL:					case UD_R_SI:	case UD_R_ESI:	case UD_R_RSI:
		return this->is_operand_base(index, { UD_R_SIL, UD_R_SI, UD_R_ESI, UD_R_RSI });

	case UD_R_DIL:					case UD_R_DI:	case UD_R_EDI:	case UD_R_RDI:
		return this->is_operand_base(index, { UD_R_DIL, UD_R_DI, UD_R_EDI, UD_R_RDI });
  
	default:
		break;
	}

	return false;
}

bool ud_instruction::is_operand_base_family(std::size_t index, std::initializer_list<ud_type> families) const
{
	for (std::initializer_list<ud_type>::const_iterator iter = families.begin(); iter != families.end(); iter++)
	{
		if (this->is_operand_base_family(index, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_base_family(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return this->is_operand_base_family(index, instruction.operand[instruction_index].base);
}

bool ud_instruction::is_operand_base_family_not(std::size_t index, ud_type family) const
{
	return (!this->is_operand_base_family(index, family));
}

bool ud_instruction::is_operand_base_family_not(std::size_t index, std::initializer_list<ud_type> families) const
{
	return (!this->is_operand_base_family(index, families));
}

bool ud_instruction::has_operand_index(std::size_t index) const
{
	return (this->operand[index].index != UD_NONE);
}

bool ud_instruction::has_operand_index_not(std::size_t index) const
{
	return (!this->has_operand_index(index));
}

bool ud_instruction::is_operand_index(std::size_t index, ud_type type) const
{
	return (this->operand[index].index == type);
}

bool ud_instruction::is_operand_index(std::size_t index, std::initializer_list<ud_type> types) const
{
	for (std::initializer_list<ud_type>::const_iterator iter = types.begin(); iter != types.end(); iter++)
	{
		if (this->is_operand_index(index, *iter))
			return true;
	}

	return false;
}
	
bool ud_instruction::is_operand_index(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (this->is_operand_index(index, instruction.operand[instruction_index].index));
}

bool ud_instruction::is_operand_index_not(std::size_t index, ud_type type) const
{
	return (!this->is_operand_index(index, type));
}

bool ud_instruction::is_operand_index_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_index(index, instruction, instruction_index));
}

bool ud_instruction::is_operand_index_by_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return this->is_operand_index(index, instruction.operand[instruction_index].base);
}

bool ud_instruction::has_operand_scale(std::size_t index) const
{
	return (this->operand[index].scale != 0);
}

bool ud_instruction::has_operand_scale_not(std::size_t index) const
{
	return (!this->has_operand_scale(index));
}

bool ud_instruction::is_operand_scale(std::size_t index, uint8_t scale) const
{
	return (this->operand[index].scale == scale);
}

bool ud_instruction::is_operand_scale(std::size_t index, std::initializer_list<uint8_t> scales) const
{
	for (std::initializer_list<uint8_t>::const_iterator iter = scales.begin(); iter != scales.end(); iter++)
	{
		if (this->is_operand_scale(index, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_scale(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (this->is_operand_scale(index, instruction.operand[instruction_index].scale));
}

bool ud_instruction::is_operand_scale_not(std::size_t index, uint8_t scale) const
{
	return (!this->is_operand_scale(index, scale));
}

bool ud_instruction::is_operand_scale_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_scale(index, instruction, instruction_index));
}

bool ud_instruction::has_operand_offset(std::size_t index) const
{
	return (this->operand[index].offset != 0);
}

bool ud_instruction::has_operand_offset_not(std::size_t index) const
{
	return (!this->has_operand_offset(index));
}

bool ud_instruction::is_operand_offset(std::size_t index, uint8_t offset) const
{
	return (this->operand[index].offset == offset);
}

bool ud_instruction::is_operand_offset(std::size_t index, std::initializer_list<uint8_t> offsets) const
{
	for (std::initializer_list<uint8_t>::const_iterator iter = offsets.begin(); iter != offsets.end(); iter++)
	{
		if (this->is_operand_offset(index, *iter))
			return true;
	}

	return false;
}

bool ud_instruction::is_operand_offset(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return this->is_operand_offset(index, instruction.operand[instruction_index].offset);
}

bool ud_instruction::is_operand_offset_not(std::size_t index, uint8_t offset) const
{
	return (!this->is_operand_offset(index, offset));
}

bool ud_instruction::is_operand_offset_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_offset(index, instruction, instruction_index));
}

bool ud_instruction::has_operand_data(std::size_t index) const
{
	if (this->is_operand_type(index, UD_OP_MEM))
		return (this->has_operand_offset(index) && this->is_operand_data_not<uint64_t>(index, 0));
	else
		return (this->is_operand_data_not<uint64_t>(index, 0));
}

bool ud_instruction::has_operand_data_not(std::size_t index) const
{
	return (!this->has_operand_data(index));
}

bool ud_instruction::compare_mnemonic(bool allow_mov, bool allow_unary, bool allow_binary)
{
	return ((allow_mov && this->is_mnemonic(UD_Imov)) ||
		(allow_unary && this->is_mnemonic({ UD_Idec, UD_Iinc, UD_Inot, UD_Ineg })) ||
		(allow_binary && this->is_mnemonic({ UD_Iadd, UD_Isub, UD_Ixor, UD_Ior, UD_Iand, UD_Ishl, UD_Ishr })));
}

bool ud_instruction::compare_mnemonic_not(bool allow_mov, bool allow_unary, bool allow_binary)
{
	return (!this->compare_mnemonic(allow_mov, allow_unary, allow_binary));
}

bool ud_instruction::compare_immediate()
{
	return (this->is_mnemonic({ UD_Iadd, UD_Isub }) && this->is_operand_type(1, UD_OP_IMM) && this->is_operand_data(1, { -1, 1 }));
}

bool ud_instruction::compare_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	ud_type base_type = instruction.operand[instruction_index].base;
	ud_size base_size = instruction.get_base_size(instruction_index);

	if (this->get_base_size(index) < base_size)
		return false;

	if (base_size == UD_SIZE_BYTE && (base_type >= UD_R_AH && base_type <= UD_R_BH))
		base_type = static_cast<ud_type>(base_type - (UD_R_AH - UD_R_AL));

	return (this->operand[index].base == base_type);
}

bool ud_instruction::compare_base_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->compare_base(index, instruction, instruction_index));
}

void ud_instruction::set_mnemonic(ud_mnemonic_code mnemonic)
{
	this->mnemonic = mnemonic;
}

void ud_instruction::set_mnemonic(ud_instruction& instruction)
{
	this->set_mnemonic(instruction.mnemonic);
}

void ud_instruction::set_prefixes(ud_instruction& instruction)
{
	this->pfx_rex = instruction.pfx_rex;
	this->pfx_seg = instruction.pfx_seg;
	this->pfx_opr = instruction.pfx_opr;
	this->pfx_adr = instruction.pfx_adr;
	this->pfx_lock = instruction.pfx_lock;
	this->pfx_str = instruction.pfx_str;
	this->pfx_rep = instruction.pfx_rep;
	this->pfx_repe = instruction.pfx_repe;
	this->pfx_repne = instruction.pfx_repne;
}

void ud_instruction::set_operand_null(std::size_t index)
{
	this->set_operand_type_null(index);
	this->set_operand_base_null(index);
	this->set_operand_index_null(index);
	this->set_operand_scale_null(index);
	this->set_operand_offset_null(index);
	this->set_operand_data_null<uint64_t>(index);
}

void ud_instruction::set_operand_type(std::size_t index, ud_type type, ud_size size)
{
	this->operand[index].type = type;
	this->operand[index].size = size;
}

void ud_instruction::set_operand_type(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_type(index, instruction.operand[instruction_index].type, static_cast<ud_size>(instruction.operand[instruction_index].size));
}

void ud_instruction::set_operand_type_null(std::size_t index)
{
	this->set_operand_type(index, UD_NONE, UD_SIZE_NONE);
}

void ud_instruction::set_operand_size(std::size_t index, ud_size size)
{
	this->operand[index].size = size;
}

void ud_instruction::set_operand_base(std::size_t index, ud_type type)
{
	this->operand[index].base = type;
}

void ud_instruction::set_operand_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_base(index, instruction.operand[instruction_index].base);
}
	
void ud_instruction::set_operand_base(std::size_t index, ud_type type, ud_size size)
{
	this->set_operand_base(index, this->base_to_size_type(type, size));
}

void ud_instruction::set_operand_base_null(std::size_t index)
{
	this->set_operand_base(index, UD_NONE);
}

void ud_instruction::set_operand_index(std::size_t index, ud_type type)
{
	this->operand[index].index = type;
}

void ud_instruction::set_operand_index(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_index(index, instruction.operand[instruction_index].index);
}

void ud_instruction::set_operand_index_null(std::size_t index)
{
	this->set_operand_index(index, UD_NONE);
}

void ud_instruction::set_operand_index_by_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_index(index, instruction.operand[instruction_index].base);
}

void ud_instruction::set_operand_scale(std::size_t index, uint8_t scale)
{
	this->operand[index].scale = scale;
}

void ud_instruction::set_operand_scale(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_scale(index, instruction.operand[instruction_index].scale);
}

void ud_instruction::set_operand_scale_null(std::size_t index)
{
	this->set_operand_scale(index, 0);
}

void ud_instruction::set_operand_scale_by_exponent(std::size_t index, uint8_t scale_exp)
{
	if (scale_exp)
		this->set_operand_scale(index, static_cast<uint8_t>(std::pow(2, scale_exp)));
	else
		this->set_operand_scale_null(index);
}

void ud_instruction::set_operand_offset(std::size_t index, uint8_t offset)
{
	this->operand[index].offset = offset;
}

void ud_instruction::set_operand_offset(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_offset(index, instruction.operand[instruction_index].offset);
}

void ud_instruction::set_operand_offset_null(std::size_t index)
{
	this->set_operand_offset(index, 0);
}