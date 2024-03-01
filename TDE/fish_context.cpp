#include "fish_context.hpp"

void fish_context::clear()
{
    wild_context::clear();

    std::fill(std::begin(fish_operands), std::end(fish_operands), FishOperand{});

    initialized_push_pop_mnemonics = false;
    initialized_unary_mnemonics = false;
    initialized_binary_mnemonics = false;
}
