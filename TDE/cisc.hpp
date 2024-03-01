#ifndef CISC_HPP_
#define CISC_HPP_

#include "oreans_base.hpp"

class cisc : public oreans_base
{
public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_entrance);
};

#endif
