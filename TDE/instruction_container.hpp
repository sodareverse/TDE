#ifndef INSTRUCTION_CONTAINER_HPP_
#define INSTRUCTION_CONTAINER_HPP_

#include "instruction_container_branch_evaluator.hpp"
#include <cstdint>

class WildContext; // Forward declaration

class InstructionContainer : public InstructionContainerBranchEvaluator {
public:
    bool decodeAssembly(ud_instruction& instruction);
    void printAssembly(FILE* file = nullptr);
    void printSyntax(WildContext& context, ud_instruction& instruction, uint32_t handler_offset, FILE* file = nullptr);

public:
    void updateIndexes();

public:
    bool hasAddress(uint32_t address) const;
    bool findAddressIndex(uint32_t address, std::size_t& index) const;
    bool findMnemonicIndex(ud_mnemonic_code mnemonic, std::size_t& index) const;
    bool findIndexByRegisterBase(ud_type base, std::size_t& index, ud_instruction& instruction);
    bool findIndexByMemoryBase(ud_type base, std::size_t operand, std::size_t& index, ud_instruction& instruction);

private:
    bool findIndex(size_type& index, predicate_function predicate) const;
    bool find(const_iterator& iter, size_type& index, predicate_function predicate) const;
};

#endif
