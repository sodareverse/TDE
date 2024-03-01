#ifndef SEGMENT_MANAGER_HPP_
#define SEGMENT_MANAGER_HPP_

#include "segment_copy.hpp"

class segment_manager
{
public:
	bool make_segment_copy(uint32_t address, std::size_t index = 0);

	bool is_segment(uint32_t address, std::size_t index = 0);
	bool in_segment_range(uint32_t address, uint32_t offset, std::size_t index = 0);
	
	std::pair<uint8_t*, uint32_t> to_segment(uint32_t address, std::size_t index = 0);
	
private:
	uint8_t* to_segment_base(uint32_t address, std::size_t index = 0);
	uint32_t to_segment_size(uint32_t address, std::size_t index = 0);

private:
	std::vector<segment_copy> vm_segments;
};

#endif