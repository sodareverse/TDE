#ifndef WILD_BASE_HPP_
#define WILD_BASE_HPP_

#include "wild_handler_parser.hpp"
#include "wild_handler.hpp"

class wild_base : public wild_handler_parser
{
	virtual bool parse_initial_handler(instruction_container& instructions) = 0;

	virtual bool parse_virtual_handler(instruction_container& instructions, uint32_t index, uint32_t compares) = 0;
	virtual bool fetch_virtual_handler(std::size_t index, wild_handler** handler) = 0;
	
	virtual bool update_argument_data() { return false; }

public:
	wild_base(wild_context& context);

public:
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);

private:
	bool parse_virtual_machine(uint32_t vm_entrance);
	
	bool trace_function(instruction_container& instructions);

	bool process_virtual_pointer(instruction_container& instructions, wild_opcode_label& label);
	void process_virtual_function(instruction_container& instructions);
	
	bool parse_initial_handlers();
	bool parse_virtual_handlers();
	
	bool parse_next_handler_offset(instruction_container& instructions);
	
private:
	uint32_t vm_function;
	uint32_t vm_entrance;
};

#endif