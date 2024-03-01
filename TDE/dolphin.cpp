#include "dolphin.hpp"

#include <idp.hpp>

dolphin::dolphin()
	: wild(this->context)
{

}

bool dolphin::is_signature(instruction_container& vm_entrance)
{
	msg("DOLPHIN machine identified.\n");
	return true;
}

bool dolphin::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions)
{
	msg("DOLPHIN machines are currently not supported.\n");
	return false;
}

bool dolphin::parse_initial_handler(instruction_container& instructions)
{
	msg("DOLPHIN attempted to parse key handler.\n");
	return false;
}
