#include "segment_copy.hpp"
#include <idp.hpp>
#include <segment.hpp>

SegmentCopy::SegmentCopy(uint32_t startAddress, uint32_t endAddress) : segmentInfo(std::make_pair(startAddress, endAddress)) {
    segmentData.resize(endAddress - startAddress);
    get_many_bytes(startAddress, &segmentData[0], endAddress - startAddress);
}

uint32_t SegmentCopy::start() const {
    return segmentInfo.first;
}

uint32_t SegmentCopy::end() const {
    return segmentInfo.second;
}

uint32_t SegmentCopy::size() const {
    return (end() - start());
}

uint8_t* SegmentCopy::data(uint32_t offset) {
    return (segmentData.data() + offset);
}
