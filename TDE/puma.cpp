#include "puma.hpp"

#include <idp.hpp>

bool puma::is_signature(instruction_container& vm_entrance)
{
	msg("[CodeDevirtualizer] PUMA machine identified.\n");
	return true;
}

bool puma::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions)
{
	msg("[CodeDevirtualizer] PUMA machines are currently not supported.\n");
	return false;
}