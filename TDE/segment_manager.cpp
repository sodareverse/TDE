#include "segment_manager.hpp"

#include <idp.hpp>
#include <segment.hpp>

bool segment_manager::make_segment_copy(uint32_t address, std::size_t index)
{
	for (int32_t seg_index = 0, seg_count = get_segm_qty(); seg_index < seg_count; seg_index++)
	{
		segment_t* segment = getnseg(seg_index);

		if (address >= segment->startEA && address < segment->endEA)
		{
			if (index < this->vm_segments.size())
				this->vm_segments.erase(this->vm_segments.begin() + index);

			this->vm_segments.insert(this->vm_segments.begin() + index, segment_copy(segment->startEA, segment->endEA));
			return true;
		}
	}

	return false;
}

bool segment_manager::is_segment(uint32_t address, std::size_t index)
{
	if (index >= this->vm_segments.size())
		return false;

	uint32_t start = this->vm_segments.at(index).start();
	uint32_t end = this->vm_segments.at(index).end();

	return (address >= start && address < end);
}

bool segment_manager::in_segment_range(uint32_t address, uint32_t offset, std::size_t index)
{
	if (index >= this->vm_segments.size())
		return false;
	
	uint32_t start = this->vm_segments.at(index).start();
	uint32_t size = this->vm_segments.at(index).size();

	return (((address - start) + offset) < size);
}

std::pair<uint8_t*, uint32_t> segment_manager::to_segment(uint32_t address, std::size_t index)
{
	return std::make_pair(this->to_segment_base(address, index), this->to_segment_size(address, index));
}

uint8_t* segment_manager::to_segment_base(uint32_t address, std::size_t index)
{
	if (!this->is_segment(address, index))
		return nullptr;
	
	uint32_t start = this->vm_segments.at(index).start();
	
	return this->vm_segments.at(index).data(address - start);
}

uint32_t segment_manager::to_segment_size(uint32_t address, std::size_t index)
{
	if (!this->is_segment(address, index))
		return 0;
	
	uint32_t start = this->vm_segments.at(index).start();
	
	return (this->vm_segments.at(index).size() - (address - start));
}