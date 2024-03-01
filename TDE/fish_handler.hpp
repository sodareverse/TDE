#ifndef FISH_HANDLER_HPP_
#define FISH_HANDLER_HPP_

#include "wild_handler.hpp"
#include "fish_context.hpp"

class fish_handler : public wild_handler
{
	enum fish_key_types
	{
		FISH_KEY_MNEMONIC = 6,
	};

	enum fish_operand_type
	{
		FISH_OPERAND_TYPE_REGISTER = 0x01,
		FISH_OPERAND_TYPE_MEMORY,
		FISH_OPERAND_TYPE_IMMEDIATE
	};

public:
	fish_handler(uint16_t index);
	
	bool update_argument_data(fish_context& context);

private:
	bool map_handler_specific(instruction_container& instructions, wild_context& context);
	bool map_handler_fish(instruction_container& instructions, fish_context& context);

private:
	bool map_handler_call(instruction_container& instructions, wild_context& context);
	bool map_handler_internal_0000(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts);
	bool map_handler_internal_0001(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts);
	bool map_handler_internal_0002(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts);
	bool map_handler_internal_0003(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts);
	bool map_handler_internal_0004(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts);
	
private:
	bool map_subhandler(instruction_container& instructions, fish_context& context, std::size_t& offset);
	
private:
	bool map_subhandler_0000(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0001(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0002(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0003(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0004(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0005(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0006(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0007(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0008(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_0009(instruction_container& instructions, fish_context& context, std::size_t& offset);
	bool map_subhandler_000A(instruction_container& instructions, fish_context& context, std::size_t& offset);
	
private:
	bool decrypt_default_data(instruction_container& instructions, wild_context& context);
	bool decrypt_fish_data(instruction_container& instructions, fish_context& context);
	
	bool parse_push_pop_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index);
	bool parse_unary_operation_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index);
	bool parse_binary_operation_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index);
	
	bool parse_handler_mnemonic(instruction_container& instructions, fish_context& context, std::size_t& index, uint8_t offset);
	
	bool find_mnemonic_key_read_instruction(instruction_container& instructions, fish_context& context, std::size_t& index, ud_instruction& instruction);
	
private:
	bool step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_fish(instruction_container& instructions, fish_context& context, opcode_reader& opcode);
	
private:
	bool step_handler_call(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_push_pop(instruction_container& instructions, fish_context& context, opcode_reader& opcode);
	bool step_handler_common_unary_operation(instruction_container& instructions, fish_context& context, opcode_reader& opcode);
	bool step_handler_common_binary_operation(instruction_container& instructions, fish_context& context, opcode_reader& opcode);
	bool step_handler_align(instruction_container& instructions, fish_context& context, opcode_reader& opcode);
	bool step_handler_xchg(instruction_container& instructions, fish_context& context, opcode_reader& opcode);

private:
	bool step_default_sequence(wild_context& context, opcode_reader& opcode);

	void parse_common_instruction(instruction_container& instructions, fish_context& context, uint32_t address, uint16_t mnemonic_key_constant, 
		uint8_t operand_0_info, uint32_t operand_0_data, uint8_t operand_1_info, int32_t operand_1_data);

	void parse_common_operand(ud_instruction& instruction, fish_context& context, std::size_t operand, uint8_t operand_info, uint32_t operand_data);

public:
	std::vector<std::pair<ud_mnemonic_code, uint8_t>> mnemonic_key_decoders;
	
	std::vector<std::pair<uint32_t, std::size_t>> subhandlers; // xx2 ;
	std::vector<std::pair<uint8_t, std::size_t>> x2;	// x2 ; <idk1, index>
};

#endif
