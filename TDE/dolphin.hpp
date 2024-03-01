#ifndef DOLPHIN_HPP_
#define DOLPHIN_HPP_

#include "wild.hpp"

#include "dolphin_handler.hpp"

class dolphin : public wild<dolphin_handler>
{
public:
	dolphin();

public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions);

private:
	bool parse_initial_handler(instruction_container& instructions);

private:
	wild_context context;
};

#endif
