#ifndef DOLPHIN_HANDLER_HPP_
#define DOLPHIN_HANDLER_HPP_

#include "wild_handler.hpp"

class dolphin_handler : public wild_handler
{
public:
	dolphin_handler(uint16_t index);

private:
	bool map_handler_specific(instruction_container& instructions, wild_context& context);
};

#endif
