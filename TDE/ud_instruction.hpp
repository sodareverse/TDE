#ifndef UD_INSTRUCTION_HPP_
#define UD_INSTRUCTION_HPP_

#include "udis86.h"

#include <initializer_list>
#include <utility>

enum ud_size : uint16_t
{
	UD_SIZE_NONE = 0,
	UD_SIZE_BYTE = 8,
	UD_SIZE_WORD = 16,
	UD_SIZE_DWORD = 32,
	UD_SIZE_FWORD = 48,
	UD_SIZE_QWORD = 64
};

class ud_instruction : public ud_t
{
	void initialize(uint64_t base_address, uint8_t mode = 32);

public:
	ud_instruction();
	ud_instruction(uint64_t base_address);
	
public:
	uint32_t get_index();
	void set_index(uint32_t index);

	uint32_t get_key_data();
	void set_key_data(uint32_t key_data);

public:
	void set_input(uint8_t* address, uint32_t size);
	void set_input(std::pair<uint8_t*, uint32_t> input);
	
	void skip_input(uint32_t length);
	void reset_input(uint32_t address);

	void set_program_counter(uint64_t counter);

	template <typename T = uint64_t>
	T get_address() const;
	
	template <typename T = uint64_t>
	T get_address_next() const;
	
	template <typename T = uint64_t>
	bool is_address(T address) const;

public:
	template <typename T = uint32_t>
	T get_operand_data(std::size_t index) const;
	
	template <typename T = uint32_t>
	void set_operand_data(std::size_t index, T data);
	
	ud_mnemonic_code get_mnemonic() const;

	ud_type get_operand_type(std::size_t index) const;
	ud_size get_operand_size(std::size_t index) const;

	ud_type get_base_type(std::size_t index) const;
	ud_type get_base_high_type(std::size_t index) const;
	ud_type get_base_size_type(std::size_t index, ud_size size) const;
	ud_size get_base_size(std::size_t index) const;
	
	ud_size get_type_size(ud_type type) const;

	ud_type base_to_size_type(ud_type base, ud_size size) const;

public: // To be removed (?)
	uint32_t get_params(uint32_t operand) const;
	uint16_t get_loword(uint32_t operand) const;

public:
	bool is_mnemonic(ud_mnemonic_code mnemonic) const;
	bool is_mnemonic(std::initializer_list<ud_mnemonic_code> mnemonics) const;
	bool is_mnemonic_not(ud_mnemonic_code mnemonic) const;
	bool is_mnemonic_not(std::initializer_list<ud_mnemonic_code> mnemonics) const;
	bool is_mnemonic_jcc() const;
	bool is_mnemonic_jcc_not() const;

	bool is_operand_null(std::size_t index) const;
	bool is_operand_not_null(std::size_t index) const;
	
	template <typename T = uint32_t>
	bool is_operand(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	template <typename T = uint32_t>
	bool is_operand_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	bool is_operand_type(std::size_t index, ud_type type, ud_size size = UD_SIZE_NONE) const;
	bool is_operand_type(std::size_t index, std::initializer_list<ud_type> types) const;
	bool is_operand_type(std::size_t index, ud_type type, std::initializer_list<ud_size> sizes) const;
	bool is_operand_type(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_type_not(std::size_t index, ud_type type, ud_size size = UD_SIZE_NONE) const;
	bool is_operand_type_not(std::size_t index, std::initializer_list<ud_type> types) const;
	bool is_operand_type_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	bool is_operand_size(std::size_t index, ud_size size) const;
	bool is_operand_size_not(std::size_t index, ud_size size) const;

	bool is_operand_sib(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;

	bool has_operand_base(std::size_t index) const;
	bool has_operand_base_not(std::size_t index) const;

	bool is_operand_base(std::size_t index, ud_type type) const;
	bool is_operand_base(std::size_t index, std::initializer_list<ud_type> types) const;
	bool is_operand_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_base_not(std::size_t index, ud_type type) const;
	bool is_operand_base_not(std::size_t index, std::initializer_list<ud_type> types) const;
	bool is_operand_base_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	bool is_operand_base_size(std::size_t index, ud_size size) const;
	bool is_operand_base_size_not(std::size_t index, ud_size size) const;
		
	bool is_operand_base_family(std::size_t index, ud_type family) const;
	bool is_operand_base_family(std::size_t index, std::initializer_list<ud_type> families) const;
	bool is_operand_base_family(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_base_family_not(std::size_t index, ud_type family) const;
	bool is_operand_base_family_not(std::size_t index, std::initializer_list<ud_type> families) const;
	
	bool has_operand_index(std::size_t index) const;
	bool has_operand_index_not(std::size_t index) const;

	bool is_operand_index(std::size_t index, ud_type type) const;
	bool is_operand_index(std::size_t index, std::initializer_list<ud_type> types) const;
	bool is_operand_index(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_index_not(std::size_t index, ud_type type) const;
	bool is_operand_index_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_index_by_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;

	bool has_operand_scale(std::size_t index) const;
	bool has_operand_scale_not(std::size_t index) const;
	
	bool is_operand_scale(std::size_t index, uint8_t scale) const;
	bool is_operand_scale(std::size_t index, std::initializer_list<uint8_t> scales) const;
	bool is_operand_scale(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_scale_not(std::size_t index, uint8_t scale) const;
	bool is_operand_scale_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	bool has_operand_offset(std::size_t index) const;
	bool has_operand_offset_not(std::size_t index) const;

	bool is_operand_offset(std::size_t index, uint8_t offset) const;
	bool is_operand_offset(std::size_t index, std::initializer_list<uint8_t> offsets) const;
	bool is_operand_offset(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool is_operand_offset_not(std::size_t index, uint8_t offset) const;
	bool is_operand_offset_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;

	bool has_operand_data(std::size_t index) const;
	bool has_operand_data_not(std::size_t index) const;
	
	template <typename T = uint32_t>
	bool is_operand_data(std::size_t index, T data) const;
	
	template <typename T = uint32_t>
	bool is_operand_data(std::size_t index, std::initializer_list<T> datas) const;

	template <typename T = uint32_t>
	bool is_operand_data(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
	template <typename T = uint32_t>
	bool is_operand_data_not(std::size_t index, T data) const;
	
	template <typename T = uint32_t>
	bool is_operand_data_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;

public:
	bool compare_mnemonic(bool allow_mov, bool allow_unary, bool allow_binary);
	bool compare_mnemonic_not(bool allow_mov, bool allow_unary, bool allow_binary);

	bool compare_immediate();

	bool compare_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	bool compare_base_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const;
	
public:
	void set_mnemonic(ud_mnemonic_code mnemonic);
	void set_mnemonic(ud_instruction& instruction);

	void set_prefixes(ud_instruction& instruction);

	template <typename T = uint32_t>
	void set_operand(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_null(std::size_t index);
	
	void set_operand_type(std::size_t index, ud_type type, ud_size size);
	void set_operand_type(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_type_null(std::size_t index);
	
	void set_operand_size(std::size_t index, ud_size size);

	void set_operand_base(std::size_t index, ud_type type);
	void set_operand_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_base(std::size_t index, ud_type type, ud_size size);
	void set_operand_base_null(std::size_t index);
	
	void set_operand_index(std::size_t index, ud_type type);
	void set_operand_index(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_index_null(std::size_t index);
	void set_operand_index_by_base(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);

	void set_operand_scale(std::size_t index, uint8_t scale);
	void set_operand_scale(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_scale_null(std::size_t index);
	void set_operand_scale_by_exponent(std::size_t index, uint8_t scale_exp);
	
	void set_operand_offset(std::size_t index, uint8_t offset);
	void set_operand_offset(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);
	void set_operand_offset_null(std::size_t index);

	template <typename T = uint32_t>
	void set_operand_data(std::size_t index, ud_instruction& instruction, std::size_t instruction_index);

	template <typename T = uint32_t>
	void set_operand_data_null(std::size_t index);

	template <typename T = uint32_t>
	void inc_operand_data(std::size_t index, T data);
	
	template <typename T = uint32_t>
	void dec_operand_data(std::size_t index, T data);

private:
	uint32_t index;
	uint32_t key_data;
};

template <typename T>
T ud_instruction::get_address() const
{
	return static_cast<T>(ud_insn_off(this));
}

template <typename T>
T ud_instruction::get_address_next() const
{
	if (this->is_operand_type(0, UD_OP_JIMM))
		return static_cast<T>(ud_insn_off(this) + ud_insn_len(this) + this->get_operand_data<T>(0));
	else
		return static_cast<T>(ud_insn_off(this) + ud_insn_len(this));
}

template <typename T>
bool ud_instruction::is_address(T address) const
{
	return (this->get_address<T>() == address);
}

template <typename T>
bool ud_instruction::is_operand(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (this->is_operand_type(index, instruction, instruction_index) &&
		this->is_operand_base(index, instruction, instruction_index) &&
		this->is_operand_index(index, instruction, instruction_index) &&
		this->is_operand_scale(index, instruction, instruction_index) &&
		this->is_operand_offset(index, instruction, instruction_index) &&
		this->is_operand_data<T>(index, instruction, instruction_index));
}

template <typename T>
bool ud_instruction::is_operand_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand<T>(index, instruction, instruction_index));
}

template <typename T>
bool ud_instruction::is_operand_data(std::size_t index, T data) const
{
	return (this->get_operand_data<T>(index) == data);
}

template <typename T>
bool ud_instruction::is_operand_data(std::size_t index, std::initializer_list<T> datas) const
{
	for (std::initializer_list<T>::const_iterator iter = datas.begin(); iter != datas.end(); iter++)
	{
		if (this->is_operand_data<T>(index, *iter))
			return true;
	}

	return false;
}

template <typename T>
bool ud_instruction::is_operand_data(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return this->is_operand_data<T>(index, instruction.get_operand_data<T>(instruction_index));
}

template <typename T>
bool ud_instruction::is_operand_data_not(std::size_t index, T data) const
{
	return (!this->is_operand_data<T>(index, data));
}

template <typename T>
bool ud_instruction::is_operand_data_not(std::size_t index, ud_instruction& instruction, std::size_t instruction_index) const
{
	return (!this->is_operand_data<T>(index, instruction, instruction_index));
}

template <typename T>
void ud_instruction::set_operand(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	this->set_operand_type(index, instruction, instruction_index);
	this->set_operand_base(index, instruction, instruction_index);
	this->set_operand_index(index, instruction, instruction_index);
	this->set_operand_scale(index, instruction, instruction_index);
	this->set_operand_offset(index, instruction, instruction_index);
	this->set_operand_data<T>(index, instruction, instruction_index);
}

template <typename T>
void ud_instruction::set_operand_data(std::size_t index, ud_instruction& instruction, std::size_t instruction_index)
{
	if (this->is_operand_type(index, UD_OP_MEM))
	{
		if (instruction.is_operand_type(instruction_index, UD_OP_MEM))
			this->set_operand_offset(index, instruction, instruction_index);
		else if (instruction.is_operand_type(instruction_index, UD_OP_IMM))
			this->set_operand_offset(index, instruction.get_operand_size(instruction_index));
	}

	this->set_operand_data<T>(index, instruction.get_operand_data<T>(instruction_index));
}

template <typename T>
void ud_instruction::set_operand_data_null(std::size_t index)
{
	this->set_operand_data<T>(index, 0);
}

template <typename T>
void ud_instruction::inc_operand_data(std::size_t index, T data)
{
	this->set_operand_data<T>(index, this->get_operand_data<T>(index) + data);
}
	
template <typename T>
void ud_instruction::dec_operand_data(std::size_t index, T data)
{
	this->set_operand_data<T>(index, this->get_operand_data<T>(index) - data);
}

#endif