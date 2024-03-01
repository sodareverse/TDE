#ifndef WILD_HANDLER_FLOW_HPP_
#define WILD_HANDLER_FLOW_HPP_

#include "wild_context.hpp"
#include "instruction_container.hpp"

class wild_handler_flow
{
protected:
	wild_handler_flow();

protected:
	bool decrypt_flow_data(instruction_container& instructions, wild_context& context);
	
private:
	bool find_read_index(instruction_container& instructions, wild_context& context, std::size_t& index);
	bool find_read_offset(instruction_container& instructions, ud_type base, std::size_t& index);
		
	bool find_add_data_index(instruction_container& instructions, wild_context& context, ud_type base, std::size_t& index);
	bool find_add_and(instruction_container& instructions, wild_context& context, ud_type base, std::size_t& index);

	bool find_sub_data_index(instruction_container& instructions, ud_type base, std::size_t& index);
	bool find_sub_negative_check(instruction_container& instructions, ud_type base, std::size_t& index);

public:
	uint32_t flow_read_index;					// idk5	; Index of the instruction that reads the opcode address for the flow handling from the vm context
	uint16_t flow_read_offset;					// idk7 ; Offset of the opcode address whose data is being read

	uint32_t flow_data_index;					// idk6 ; Index of the instruction that reads data for the flow handling from the opcode address

	std::vector<uint32_t> flow_key_indexes;		// x3 ; Indexes of the instructions that accesses keys for modification of the flow handling opcode data
	
	uint16_t flow_mutation_mnemonic;			// idk10 ; The mnemonic of the instruction that mutates the key for the flow handling opcode data
	uint32_t flow_mutation_index;				// idk8 ; Index of the instruction that reads the mutation key for the flow handling opcode data
	uint32_t flow_mutation_constant;			// idk9 ; The data constant that is used on the mutation key for the flow handling opcode data
};

#endif