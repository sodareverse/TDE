#ifndef TIGER_CONTEXT_HPP_
#define TIGER_CONTEXT_HPP_

#include "wild_context.hpp"

class tiger_context : public wild_context
{
	typedef struct tiger_operand
	{
		bool is_found;			// idk1/idk2
		uint16_t operand_data;	// idk3/idk5
		uint16_t operand_info;	// idk4/idk6
	} tiger_operand;

public:
	void clear();

public:
	tiger_operand tiger_operands[2];
};

#endif