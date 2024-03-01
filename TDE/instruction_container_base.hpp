#ifndef INSTRUCTION_CONTAINER_BASE_HPP_
#define INSTRUCTION_CONTAINER_BASE_HPP_

#include "ud_instruction.hpp"

#include <functional>
#include <vector>

class instruction_container_base
{
protected:
	typedef ud_instruction container_type;

	typedef std::vector<container_type>::iterator iterator;
	typedef std::vector<container_type>::const_iterator const_iterator;

	typedef std::vector<container_type>::reference reference;
	typedef std::vector<container_type>::const_reference const_reference;
	
	typedef std::vector<container_type>::size_type size_type;
	typedef std::vector<container_type>::value_type value_type;

	typedef std::function<bool(value_type const&)> predicate_function;

public:
	bool empty() const;
	bool bounds(size_type offset, size_type size = 0) const;

	size_type size() const;
	
	void clear();
	void remove(size_type offset, size_type size = 0);
	
	void push_back(value_type const& value);
	void pop_back();
	
	reference at(size_type index = 0);
	const_reference at(size_type index = 0) const;

	reference front();
	reference back();
	
	iterator begin();
	const_iterator begin() const;
	
	iterator end();
	const_iterator end() const;

	const_iterator cbegin() const;
	const_iterator cend() const;

private:
	std::vector<container_type> instructions;
};

#endif