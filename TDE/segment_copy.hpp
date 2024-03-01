#ifndef SEGMENT_COPY_HPP_
#define SEGMENT_COPY_HPP_

#include <stdint.h>
#include <vector>

class segment_copy
{
public:
	segment_copy(uint32_t start_address, uint32_t end_address);

	uint32_t start() const;
	uint32_t end() const;

	uint32_t size() const;
	uint8_t* data(uint32_t offset = 0);

private:
	std::pair<uint32_t, uint32_t> segment_info;
	std::vector<uint8_t> segment_data;
};

#endif