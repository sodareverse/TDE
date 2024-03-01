#ifndef SHARK_HPP_
#define SHARK_HPP_

#include "wild_hybrid_base.hpp"

#include "fish.hpp"
#include "tiger.hpp"

class shark : public wild_hybrid_base<fish, tiger>
{
public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);
};

/*

*/

#endif