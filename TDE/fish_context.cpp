#include "fish_context.hpp"

void fish_context::clear()
{
	this->wild_context::clear();

	memset(this->fish_operands, 0, sizeof(this->fish_operands));

	this->initialized_push_pop_mnemonics = false;
	this->initialized_unary_mnemonics = false;
	this->initialized_binary_mnemonics = false;
}
