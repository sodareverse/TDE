#ifndef OREANS_BASE_HPP_
#define OREANS_BASE_HPP_

#include "instruction_container.hpp"

class oreans_base
{
public:
	virtual bool is_signature(instruction_container& vm_entrance);
	virtual bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);
};

#endif