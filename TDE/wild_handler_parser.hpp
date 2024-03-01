#ifndef WILD_HANDLER_PARSER_HPP_
#define WILD_HANDLER_PARSER_HPP_

#include "wild_handler_tracer.hpp"

class wild_handler_parser : public wild_handler_tracer
{
protected:
	wild_handler_parser(wild_context& context);
	
protected:
	void decode_virtual_handler(instruction_container& instructions, uint32_t vm_handler_offset, uint32_t& compares);
	
private:
	void deobfuscate_vm_context_access(instruction_container& instructions);
	void deobfuscate_unused_instructions(instruction_container& instructions);
	
	void backtrace_base_to_root(instruction_container& instructions, std::size_t index, uint8_t operand);
};

#endif