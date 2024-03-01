#ifndef PUMA_HPP_
#define PUMA_HPP_

#include "wild_hybrid_base.hpp"

#include "tiger.hpp"
#include "fish.hpp"

class puma : public wild_hybrid_base<tiger, fish>
{
public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);
};

/*

*/

#endif