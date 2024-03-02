#ifndef WILD_OPCODE_LABEL_MANAGER_HPP_
#define WILD_OPCODE_LABEL_MANAGER_HPP_

#include "wild_opcode_label.hpp"

#include <algorithm>
#include <iterator>
#include <vector>

class wild_opcode_label_manager
{
public:
    void reset_labels()
    {
        this->virtual_opcode_labels.clear();
    }

public:
    bool find_unread_label(std::vector<wild_opcode_label>::iterator& iter)
    {
        iter = std::find_if(this->virtual_opcode_labels.begin(), this->virtual_opcode_labels.end(), [&](wild_opcode_label const& label) -> bool
        {
            return (!label.is_read);
        });
    
        return (iter != this->virtual_opcode_labels.end());
    }

    bool find_label_at_address(std::vector<wild_opcode_label>::iterator& iter, uint32_t address)
    {
        iter = std::find_if(this->virtual_opcode_labels.begin(), this->virtual_opcode_labels.end(), [&](wild_opcode_label const& label) -> bool
        {
            return (label.address == address);
        });
    
        return (iter != this->virtual_opcode_labels.end());
    }

public:
    bool exists_label(uint32_t address)
    {
        std::vector<wild_opcode_label>::iterator iter;
        return this->find_label_at_address(iter, address);
    }

    void create_label(uint32_t address, uint32_t offset)
    {
        if (!this->exists_label(address))
            this->virtual_opcode_labels.push_back(wild_opcode_label(address, offset));
    }

protected:
    std::vector<wild_opcode_label> virtual_opcode_labels;
};

#endif
