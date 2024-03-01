#ifndef WILD_OPCODE_LABEL_HPP_
#define WILD_OPCODE_LABEL_HPP_

#include <stdint.h>

typedef struct wild_opcode_label
{
	wild_opcode_label(uint32_t address, uint32_t offset)
	{
		this->is_read = false;

		this->address = address;
		this->offset = offset;
	}
	
	bool is_read;

	uint32_t address;
	uint32_t offset;
} wild_opcode_label;

#endif