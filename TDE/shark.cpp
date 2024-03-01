#include "shark.hpp"

#include <idp.hpp>

bool shark::is_signature(instruction_container& vm_entrance)
{
	msg("[CodeDevirtualizer] SHARK machine identified.\n");
	return true;
}

bool shark::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions)
{
	msg("[CodeDevirtualizer] SHARK machines are currently not supported.\n");
	return false;
}