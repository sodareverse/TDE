#ifndef FISH_CONTEXT_HPP_
#define FISH_CONTEXT_HPP_

#include "wild_context.hpp"

class fish_context : public wild_context
{
	typedef struct fish_operand
	{
		bool is_found;			// 0 idea what this does
		uint16_t operand_data;	// 0 idea what this does
		uint16_t operand_info;	// 0 idea what this does
	} fish_operand;

public:
	void clear();

public:
	fish_operand fish_operands[2];
	
	bool initialized_push_pop_mnemonics;
	bool initialized_unary_mnemonics;
	bool initialized_binary_mnemonics; // stupid ways of initializing and mocking. but ok.
};

#endif
