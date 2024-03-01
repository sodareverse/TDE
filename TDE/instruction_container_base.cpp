#include "instruction_container_base.hpp"

bool instruction_container_base::empty() const
{
	return this->instructions.empty();
}

bool instruction_container_base::bounds(size_type offset, size_type size) const
{
	bool offset_bounds = (offset >= 0 && offset < this->size());
	bool size_bounds = ((offset + size) >= 0 && (offset + size) < this->size());

	return (offset_bounds && size_bounds);
}

instruction_container_base::size_type instruction_container_base::size() const
{
	return this->instructions.size();
}

void instruction_container_base::clear()
{
	this->instructions.clear();
}

void instruction_container_base::remove(instruction_container_base::size_type offset, instruction_container_base::size_type size)
{
	instruction_container_base::const_iterator first = instructions.cbegin() + offset;

	if (size == 0)
		this->instructions.erase(first);
	else
		this->instructions.erase(first, first + size);
}

void instruction_container_base::push_back(value_type const& value)
{
	return this->instructions.push_back(value);
}

void instruction_container_base::pop_back()
{
	return this->instructions.pop_back();
}

instruction_container_base::reference instruction_container_base::at(instruction_container_base::size_type index)
{
	return this->instructions.at(index);
}

instruction_container_base::const_reference instruction_container_base::at(instruction_container_base::size_type index) const
{
	return this->instructions.at(index);
}

instruction_container_base::reference instruction_container_base::front()
{
	return this->instructions.front();
}

instruction_container_base::reference instruction_container_base::back()
{
	return this->instructions.back();
}

instruction_container_base::iterator instruction_container_base::begin()
{
	return this->instructions.begin();
}

instruction_container_base::const_iterator instruction_container_base::begin() const
{
	return this->instructions.begin();
}

instruction_container_base::iterator instruction_container_base::end()
{
	return this->instructions.end();
}

instruction_container_base::const_iterator instruction_container_base::end() const
{
	return this->instructions.end();
}

instruction_container_base::const_iterator instruction_container_base::cbegin() const
{
	return this->instructions.cbegin();
}

instruction_container_base::const_iterator instruction_container_base::cend() const
{
	return this->instructions.cend();
}