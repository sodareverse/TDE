#include "tiger_context.hpp"

void tiger_context::clear()
{
	this->wild_context::clear();

	memset(this->tiger_operands, 0, sizeof(this->tiger_operands));
}