#ifndef WILD_HANDLER_KEYS_HPP_
#define WILD_HANDLER_KEYS_HPP_

#include "wild_context.hpp"

#include <functional>

class wild_handler_key
{
	typedef std::function<bool(wild_context const&, wild_handler_key const&)> condition_predicate;

public:
	wild_handler_key();

	bool perform(wild_context& context, uint32_t* data);

public:
    bool operator<(wild_handler_key const& key) const;

public:
	uint16_t id;					// idk1 ; The ID of the key (offset in the vm context)
	uint32_t index;					// idk2 ; The index of the instruction (in the deobfuscated handler vector)

	ud_mnemonic_code mnemonic;		// idk6 ; The mnemonic of the key access instruction
	uint8_t operand;				// idk3 ; The operand that accesses the key
	
	ud_type type;					// idk5 ; size of key and type of data
	ud_size size;

	bool direct_key_parameter;		// idk4 ; Determines if the key gets its data directly from another key, in which case param will contain the key id.
	uint32_t parameter;				// idk7 ; The parameter for the key (reg/size for register, data for immediate)
	
	condition_predicate condition;	// Type of protection template (if any)
};

#endif