#ifndef FISH_HPP_
#define FISH_HPP_

#include "wild.hpp"

#include "fish_context.hpp"
#include "fish_handler.hpp"

class fish : public wild<fish_handler>
{
public:
	fish();

public:
	bool is_signature(instruction_container& vm_entrance);
	
private:
	bool parse_initial_handler(instruction_container& instructions);

private:
	bool update_argument_data();

private:
	fish_context context;
};

#endif
