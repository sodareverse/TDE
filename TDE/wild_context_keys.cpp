#include "wild_context_keys.hpp"

void wild_context_keys::reset_keys()
{
	this->keys.clear();
}

void wild_context_keys::reset_key_data()
{
	for (std::size_t i = 0; i < this->keys.size(); i++)
		this->keys.at(i).second = 0;
}

void wild_context_keys::add_key(uint32_t offset)
{
	this->keys.push_back(std::make_pair(offset, 0));
}

bool wild_context_keys::set_key(uint32_t offset, uint32_t data)
{
	for (std::size_t i = 0; i < this->keys.size(); i++)
	{
		if (this->keys.at(i).first == offset)
		{
			this->keys.at(i).second = data;
			return true;
		}
	}

	return false;
}

bool wild_context_keys::get_key(uint32_t offset, uint32_t* data) const
{
	for (std::size_t i = 0; i < this->keys.size(); i++)
	{
		if (this->keys.at(i).first == offset)
		{
			if (data != nullptr)
				*data = this->keys.at(i).second;

			return true;
		}
	}
		
	return false;
}

uint32_t wild_context_keys::get_key_offset(uint8_t index) const
{
	return (index < this->keys.size() ? this->keys.at(index).first : 0);
}

uint32_t wild_context_keys::get_key_data(uint8_t index) const
{
	return (index < this->keys.size() ? this->keys.at(index).second : 0);
}