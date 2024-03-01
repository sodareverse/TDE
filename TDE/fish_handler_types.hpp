#ifndef FISH_HANDLER_TYPES_HPP_
#define FISH_HANDLER_TYPES_HPP_

#include <stdint.h>

enum fish_handler_types : uint16_t
{
	FISH_HANDLER_PUSH_POP = 0x1000,
	FISH_HANDLER_COMMON_UNARY_OPERATION,
	FISH_HANDLER_COMMON_BINARY_OPERATION,
	FISH_HANDLER_ALIGN,
	FISH_HANDLER_XCHG,

	FISH_HANDLER_COUNT,
};

enum fish_subhandler_types : uint16_t
{
	/*
		decode idk4/idk6 -> $1
		compare $1 to 0x2 (else: skip rest)

		decode idk3/idk5 -> $2
		and $2,0xFFFF
		add $2,VM_CONTEXT

		decode operand size -> $3
		
		mov $2,[$2]
		encode $2 -> VM_REG
		
		compare $3 to 0x1 (if: mov $2,byte ptr [$2])
		compare $3 to 0x2 (if: mov $2,word ptr [$2])
		compare $3 to 0x3 (if: mov $2,dword ptr [$2])
		
		encode $2 -> idk3/idk5
	*/
	FISH_UNKNOWN_SUBHANDLER_0000 = 0x0000,		// 
	
	/*
		decode idk4/idk6 -> $1
		compare $1 to 0x02 (else: skip rest)

		decode idk3/idk5 -> $2
		and $2,0xFFFF
		add $2,VM_CONTEXT

		decode operand size -> $3

		mov $2,[$2]
		
		compare $3 to 0x1 (if: mov $2,byte ptr [$2])
		compare $3 to 0x2 (if: mov $2,word ptr [$2])
		compare $3 to 0x3 (if: mov $2,dword ptr [$2])
		
		encode $2 -> idk3/idk5
	*/
	FISH_UNKNOWN_SUBHANDLER_0001,				// 

	FISH_UNKNOWN_SUBHANDLER_0002,				// Same as 0000
	
	FISH_SUBHANDLER_LOAD_STORE,

	/*
		decode idk4/idk6 -> $1
		compare $1 to 0x01 (else: skip rest)

		decode idk3/idk5 -> $2
		and $2,0xFFFF
		add $2,VM_CONTEXT

		encode $2 -> VM_REG						; addr
		encode dword ptr [$2] -> idk3/idk5		; value
	*/
	FISH_UNKNOWN_SUBHANDLER_0004,				

	/*
		decode idk4/idk6 -> $1
		compare $1 to 0x01 (else: skip rest)

		decode idk3/idk5 -> $2
		and $2,0xFFFF
		add $2,VM_CONTEXT

		encode [$2] -> idk3/idk5
	*/
	FISH_UNKNOWN_SUBHANDLER_0005,

	FISH_SUBHANDLER_LOAD_OPERAND_INFO,
	FISH_SUBHANDLER_ALIGN_REGISTER,
	FISH_SUBHANDLER_LOAD_OPERAND_DATA,
	FISH_SUBHANDLER_LOAD_MNEMONIC,
	FISH_SUBHANDLER_RESET_INTERNAL_STATE,

	FISH_SUBHANDLER_PROTECTION_TEMPLATE_0000,

	FISH_SUBHANDLER_COUNT,

	FISH_INVALID_SUBHANDLER = 0xFFFF,
};

#endif
