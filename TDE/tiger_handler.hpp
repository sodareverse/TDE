#ifndef TIGER_HANDLER_HPP_
#define TIGER_HANDLER_HPP_

#include "wild_handler.hpp"
#include "tiger_context.hpp"

class tiger_handler : public wild_handler
{
	enum tiger_key_types
	{
		TIGER_KEY_OPERAND_1 = 5,
		TIGER_KEY_OPERAND_0,
	};
	
	typedef struct tiger_operand_decoder
	{
		ud_mnemonic_code mnemonic;
		ud_size size;
		uint32_t data;
	} tiger_operand_decoder;

	typedef struct tiger_operand
	{
		ud_type type;
		ud_size size;
		std::size_t index;
		std::vector<tiger_operand_decoder> key_decoders;
	} tiger_operand;

public:
	tiger_handler(uint16_t index);
	
	bool update_argument_data(tiger_context& context);

private:
	bool map_handler_specific(instruction_container& instructions, wild_context& context);
	bool map_handler_tiger(instruction_container& instructions, tiger_context& context);

private:
	bool map_handler_call(instruction_container& instructions, tiger_context& context);

	bool map_handler_nop(instruction_container& instructions, tiger_context& context);
	bool map_handler_push(instruction_container& instructions, tiger_context& context);
	bool map_handler_pop(instruction_container& instructions, tiger_context& context);
	
	bool map_handler_inc(instruction_container& instructions, tiger_context& context);
	bool map_handler_dec(instruction_container& instructions, tiger_context& context);
	bool map_handler_not(instruction_container& instructions, tiger_context& context);
	bool map_handler_neg(instruction_container& instructions, tiger_context& context);

	bool map_handler_mov(instruction_container& instructions, tiger_context& context);
	bool map_handler_movsx(instruction_container& instructions, tiger_context& context);
	bool map_handler_movzx(instruction_container& instructions, tiger_context& context);
	bool map_handler_add(instruction_container& instructions, tiger_context& context);
	bool map_handler_sub(instruction_container& instructions, tiger_context& context);
	bool map_handler_and(instruction_container& instructions, tiger_context& context);
	bool map_handler_xor(instruction_container& instructions, tiger_context& context);
	bool map_handler_or(instruction_container& instructions, tiger_context& context);
	bool map_handler_shl(instruction_container& instructions, tiger_context& context);
	bool map_handler_shr(instruction_container& instructions, tiger_context& context);
	bool map_handler_rcl(instruction_container& instructions, tiger_context& context);
	bool map_handler_rcr(instruction_container& instructions, tiger_context& context);
	bool map_handler_rol(instruction_container& instructions, tiger_context& context);
	bool map_handler_ror(instruction_container& instructions, tiger_context& context);
	bool map_handler_cmp(instruction_container& instructions, tiger_context& context);
	bool map_handler_test(instruction_container& instructions, tiger_context& context);
	bool map_handler_imul(instruction_container& instructions, tiger_context& context);

	bool map_unary_operation(instruction_container& instructions, tiger_context& context, std::size_t& index, ud_mnemonic_code mnemonic);

private:
	bool decrypt_tiger_data(instruction_container& instructions, tiger_context& context);
	bool decrypt_tiger_operand_data(instruction_container& instructions, tiger_context& context, uint8_t operand_key, std::vector<tiger_operand_decoder>& key_decoders);
	
	bool find_operand_key_read_instruction(instruction_container& instructions, tiger_context& context, uint8_t operand_key, std::size_t& index, ud_instruction& instruction);
	
private:
	bool step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_tiger(instruction_container& instructions, tiger_context& context, opcode_reader& opcode);

private:
	bool step_handler_nop(instruction_container& instructions, tiger_context& context, opcode_reader& opcode);
	bool step_handler_push(instruction_container& instructions, tiger_context& context, opcode_reader& opcode);
	bool step_handler_pop(instruction_container& instructions, tiger_context& context, opcode_reader& opcode);

private:
	tiger_operand operands[2];
};

#endif