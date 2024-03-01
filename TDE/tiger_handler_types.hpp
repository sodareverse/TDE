#ifndef TIGER_HANDLER_TYPES_HPP_
#define TIGER_HANDLER_TYPES_HPP_

#include <stdint.h>

enum tiger_handler_types : uint16_t
{
	TIGER_HANDLER_NOP = 0x2000,

	TIGER_HANDLER_PUSH,
	TIGER_HANDLER_POP,

	TIGER_HANDLER_INC,
	TIGER_HANDLER_DEC,
	TIGER_HANDLER_NOT,
	TIGER_HANDLER_NEG,
	
	TIGER_HANDLER_MOV,
	TIGER_HANDLER_MOVSX,
	TIGER_HANDLER_MOVZX,

	TIGER_HANDLER_ADD,
	TIGER_HANDLER_SUB,
	TIGER_HANDLER_AND,
	TIGER_HANDLER_XOR,
	TIGER_HANDLER_OR,

	TIGER_HANDLER_SHL,
	TIGER_HANDLER_SHR,
	TIGER_HANDLER_RCL,
	TIGER_HANDLER_RCR,
	TIGER_HANDLER_ROL,
	TIGER_HANDLER_ROR,

	TIGER_HANDLER_CMP,
	TIGER_HANDLER_TEST,
	
	TIGER_HANDLER_IMUL,

	TIGER_HANDLER_COUNT,
};

#endif