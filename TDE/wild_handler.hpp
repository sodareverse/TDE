#ifndef WILD_HANDLER_HPP_
#define WILD_HANDLER_HPP_

#include "wild_context.hpp"

#include "wild_handler_flow.hpp"
#include "wild_handler_key.hpp"
#include "wild_handler_types.hpp"

#include "wild_opcode_reader.hpp"

#define HAS_KEY_DATA_FLAG	0x80000000

class wild_handler : public wild_handler_flow
{
	typedef struct wild_opcode_region
	{
		uint16_t opcode_offset;
		ud_size opcode_size;

		uint32_t index_start;
		uint32_t index_end;
	} wild_opcode_region;

	enum opcode_size_type
	{
		OPCODE_SIZE_SUB = 0x4000,
		OPCODE_SIZE_RETN = 0x8000,
		OPCODE_SIZE_INVALID = 0xFFFF
	};
	
	virtual bool map_handler_specific(instruction_container& instructions, wild_context& context);
	virtual bool step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	
public:
	wild_handler(uint16_t index);
	
	uint16_t get_id();
	bool is_flow_type();

public:
	bool decrypt(instruction_container& instructions, wild_context& context, uint32_t compares);

private:
	bool decrypt_key_data(instruction_container& instructions, wild_context& context);
	void decrypt_key_protection_template(instruction_container& instructions, wild_context& context);
	
protected:
	std::size_t find_first_key_after(std::size_t index);
	std::size_t find_last_key_before(std::size_t index);
	
private:
	void decrypt_opcode_size(instruction_container& instructions, wild_context& context);
	void decrypt_opcode_regions(instruction_container& instructions, wild_context& context);

private:
	bool map_handler(instruction_container& instructions, wild_context& context);
	
	bool map_handler_jmp(instruction_container& instructions, wild_context& context);
	bool map_handler_jcc(instruction_container& instructions, wild_context& context);
	bool map_handler_retn(instruction_container& instructions, wild_context& context);
	bool map_handler_undef(instruction_container& instructions, wild_context& context);
	bool map_handler_lods(instruction_container& instructions, wild_context& context);
	bool map_handler_stos(instruction_container& instructions, wild_context& context);
	bool map_handler_scas(instruction_container& instructions, wild_context& context);
	bool map_handler_cmps(instruction_container& instructions, wild_context& context);
	bool map_handler_movs(instruction_container& instructions, wild_context& context);
	bool map_handler_eflags(instruction_container& instructions, wild_context& context);
	bool map_handler_reset_eflags(instruction_container& instructions, wild_context& context);
	bool map_handler_reset(instruction_container& instructions, wild_context& context);
	bool map_handler_stack(instruction_container& instructions, wild_context& context);
	bool map_handler_crypt(instruction_container& instructions, wild_context& context);

private:
	bool parse_jcc_parameters(instruction_container& instructions, wild_context& context);
	bool parse_eflags_parameters(instruction_container& instructions, wild_context& context);
	
protected:
	bool perform_key_sequence(wild_context& context, uint32_t first_index, uint32_t last_index, uint32_t* data);
	
public:
	bool step_handler(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	
private:
	bool step_handler_jmp_inside(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_jmp_outside_register(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_jmp_outside_memory(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_jmp_outside_immediate(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_jcc_inside(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_jcc_outside(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_ret(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_undef(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_lods(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_stos(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_scas(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_cmps(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_movs(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_pushfd(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_popfd(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_eflags(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_restore_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_load_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_store_stack(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_reset_eflags(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_reset(instruction_container& instructions, wild_context& context, opcode_reader& opcode);
	bool step_handler_crypt(instruction_container& instructions, wild_context& context, opcode_reader& opcode);

protected:
	bool step_opcode_regions(wild_context& context, opcode_reader& opcode);
	bool step_handler_flow(wild_context& context, uint16_t raw_handler_offset, bool skip_flow_mutation);

protected:
	uint16_t id;
	uint16_t index;
	uint16_t opcode_size;
	uint8_t cmp_count;

	std::vector<wild_handler_key> key_accessors;		// x1 ; 

	uint16_t opcode_offsets[16];						// xx1
	std::vector<wild_opcode_region> opcode_regions;
};

#endif