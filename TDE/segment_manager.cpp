#include "segment_manager.hpp"
#include <idp.hpp>
#include <segment.hpp>

bool SegmentManager::makeSegmentCopy(uint32_t address, std::size_t index) {
    for (int32_t segIndex = 0, segCount = get_segm_qty(); segIndex < segCount; ++segIndex) {
        segment_t* segment = getnseg(segIndex);
        if (address >= segment->startEA && address < segment->endEA) {
            if (index < vmSegments.size())
                vmSegments.erase(vmSegments.begin() + index);
            vmSegments.insert(vmSegments.begin() + index, SegmentCopy(segment->startEA, segment->endEA));
            return true;
        }
    }
    return false;
}

bool SegmentManager::isSegment(uint32_t address, std::size_t index) {
    if (index >= vmSegments.size())
        return false;
    uint32_t start = vmSegments.at(index).start();
    uint32_t end = vmSegments.at(index).end();
    return (address >= start && address < end);
}

bool SegmentManager::inSegmentRange(uint32_t address, uint32_t offset, std::size_t index) {
    if (index >= vmSegments.size())
        return false;
    uint32_t start = vmSegments.at(index).start();
    uint32_t size = vmSegments.at(index).size();
    return ((address - start) + offset) < size;
}

std::pair<uint8_t*, uint32_t> SegmentManager::toSegment(uint32_t address, std::size_t index) {
    return std::make_pair(toSegmentBase(address, index), toSegmentSize(address, index));
}

uint8_t* SegmentManager::toSegmentBase(uint32_t address, std::size_t index) {
    if (!isSegment(address, index))
        return nullptr;
    uint32_t start = vmSegments.at(index).start();
    return vmSegments.at(index).data(address - start);
}

uint32_t SegmentManager::toSegmentSize(uint32_t address, std::size_t index) {
    if (!isSegment(address, index))
        return 0;
    uint32_t start = vmSegments.at(index).start();
    return (vmSegments.at(index).size() - (address - start));
}
