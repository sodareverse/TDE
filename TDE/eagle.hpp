#ifndef EAGLE_HPP_
#define EAGLE_HPP_

#include "wild_hybrid_base.hpp"

#include "fish.hpp"
#include "dolphin.hpp"

class eagle : public wild_hybrid_base<fish, dolphin>
{
public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);
};

#endif
