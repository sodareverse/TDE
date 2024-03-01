#ifndef FISH_CONTEXT_HPP_
#define FISH_CONTEXT_HPP_

#include "wild_context.hpp"

class fish_context : public wild_context
{
public:
    fish_context() : initialized_push_pop_mnemonics(false),
                     initialized_unary_mnemonics(false),
                     initialized_binary_mnemonics(false) {}

    void clear();

    class FishOperand
    {
    public:
        bool is_found;          // Still no idea what this is
        uint16_t operand_data;  // Still no idea what this is
        uint16_t operand_info;  // Still no idea what this is
    };

    FishOperand fish_operands[2];

private:
    bool initialized_push_pop_mnemonics;
    bool initialized_unary_mnemonics;
    bool initialized_binary_mnemonics;
};

#endif
