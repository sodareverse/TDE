#include "cisc.hpp"

#include <idp.hpp>

bool cisc::is_signature(instruction_container& vm_entrance)
{
	msg("CISC machine identified.\n");
	return true;
}

bool cisc::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_entrance)
{
	msg("CISC machines are currently not supported.\n");
	return false;
}
