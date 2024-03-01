#ifndef WILD_HPP_
#define WILD_HPP_

#include "wild_base.hpp"

template <typename T>
class wild : public wild_base
{
	static_assert(std::is_base_of<wild_handler, T>::value, "Handler type in class 'wild' must be derived from class 'wild_handler'.");

public:
	wild(wild_context& context)
		: wild_base(context)
	{

	}

protected:
	bool parse_virtual_handler(instruction_container& instructions, uint32_t index, uint32_t compares)
	{
		T handler(index);

		if (!handler.decrypt(instructions, this->context, compares))
			return false;

		this->handlers.push_back(handler);
		return true;
	}

	bool fetch_virtual_handler(std::size_t index, wild_handler** handler)
	{
		if (index >= this->handlers.size())
			return false;

		*handler = &this->handlers.at(index);
		return true;
	}
	
protected:
	std::vector<T> handlers;
};

#endif