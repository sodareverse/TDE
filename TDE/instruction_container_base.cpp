#include "instruction_container_base.hpp"

bool instruction_container_base::empty() const {
    return instructions.empty();
}

bool instruction_container_base::bounds(size_type offset, size_type size) const {
    bool offsetBounds = (offset < size());
    bool sizeBounds = (size == 0) ? true : (offset + size <= size());
    return (offsetBounds && sizeBounds);
}

instruction_container_base::size_type instruction_container_base::size() const {
    return instructions.size();
}

void instruction_container_base::clear() {
    instructions.clear();
}

void instruction_container_base::remove(size_type offset, size_type size) {
    if (size == 0)
        instructions.erase(instructions.begin() + offset);
    else
        instructions.erase(instructions.begin() + offset, instructions.begin() + offset + size);
}

void instruction_container_base::push_back(const value_type& value) {
    instructions.push_back(value);
}

void instruction_container_base::pop_back() {
    instructions.pop_back();
}

instruction_container_base::reference instruction_container_base::at(size_type index) {
    return instructions.at(index);
}

instruction_container_base::const_reference instruction_container_base::at(size_type index) const {
    return instructions.at(index);
}

instruction_container_base::reference instruction_container_base::front() {
    return instructions.front();
}

instruction_container_base::reference instruction_container_base::back() {
    return instructions.back();
}

instruction_container_base::iterator instruction_container_base::begin() {
    return instructions.begin();
}

instruction_container_base::const_iterator instruction_container_base::begin() const {
    return instructions.begin();
}

instruction_container_base::iterator instruction_container_base::end() {
    return instructions.end();
}

instruction_container_base::const_iterator instruction_container_base::end() const {
    return instructions.end();
}

instruction_container_base::const_iterator instruction_container_base::cbegin() const {
    return instructions.cbegin();
}

instruction_container_base::const_iterator instruction_container_base::cend() const {
    return instructions.cend();
}
