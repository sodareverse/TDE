#include "dolphin_handler.hpp"

#include <idp.hpp>

dolphin_handler::dolphin_handler(uint16_t index)
	: wild_handler(index)
{

}

bool dolphin_handler::map_handler_specific(instruction_container& instructions, wild_context& context)
{
	msg("Attempting to map specific handler of type DOLPHIN: %04X.\n", this->index);
	return false;
}
