#ifndef WILD_OPCODE_READER_HPP_
#define WILD_OPCODE_READER_HPP_

#include <stdint.h>

class opcode_reader
{
public:
	opcode_reader(uint8_t* opcode_address)
		: opcode_address(opcode_address)
	{

	}

	template <typename T>
	T read(uint32_t offset)
	{
		if (this->opcode_address != 0)
			return *reinterpret_cast<T*>(this->opcode_address + offset);

		return static_cast<T>(0);
	}

private:
	uint8_t* opcode_address;
};

#endif