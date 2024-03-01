#include "segment_copy.hpp"

#include <idp.hpp>
#include <segment.hpp>

segment_copy::segment_copy(uint32_t start_address, uint32_t end_address)
{
	this->segment_info = std::make_pair(start_address, end_address);

	this->segment_data.resize(end_address - start_address);
	get_many_bytes(start_address, &this->segment_data[0], end_address - start_address);
}

uint32_t segment_copy::start() const
{
	return this->segment_info.first;
}

uint32_t segment_copy::end() const
{
	return this->segment_info.second;
}

uint32_t segment_copy::size() const
{
	return (this->end() - this->start());
}

uint8_t* segment_copy::data(uint32_t offset)
{
	return (this->segment_data.data() + offset);
}