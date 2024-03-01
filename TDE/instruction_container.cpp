#include "instruction_container.hpp"
#include "wild_context.hpp"
#include <idp.hpp>
#include <algorithm>

bool instruction_container::decodeAssembly(ud_instruction& instruction) {
    int err = ud_disassemble(&instruction);
    if (err != 0) {
        push_back(instruction);
        return true;
    } else {
        msg("Decode err: %d. PC is %08x\n", err, instruction.pc);
        return false;
    }
}

void instruction_container::printAssembly(FILE* file) {
    for (const auto& instruction : *this) {
        instruction.translator(&instruction);
        if (file)
            fprintf(file, "%016llx %s\n", instruction.get_address(), ud_insn_asm(&instruction));
        else
            msg("%016llx %s\n", instruction.get_address(), ud_insn_asm(&instruction));
    }
}

void instruction_container::printSyntax(WildContext& context, ud_instruction& instruction, uint32_t handler_offset, FILE* file) {
    instruction.translator(&instruction);
    if (file)
        fprintf(file, "{%04X} [%08X-%08X-%08X-%08X-%08X] %s\n", handler_offset, context.step_params[0], context.step_params[1], context.step_params[2], context.step_params[3], context.step_params[4], ud_insn_asm(&instruction));
    else
        msg("%08X {%04X} [%08X-%08X-%08X-%08X-%08X] %s\n", instruction.get_address<uint32_t>(), 
            handler_offset, context.step_params[0], context.step_params[1], context.step_params[2], context.step_params[3], context.step_params[4], ud_insn_asm(&instruction));
}

void instruction_container::updateIndexes() {
    for (size_t i = 0; i < size(); ++i)
        at(i).setIndex(i);
}

bool instruction_container::hasAddress(uint32_t address) const {
    auto iter = std::find_if(begin(), end(), [address](const auto& value) {
        return value.isAddress<uint32_t>(address);
    });
    return iter != end();
}

bool instruction_container::findAddressIndex(uint32_t address, size_t& index) const {
    auto iter = std::find_if(begin(), end(), [address](const auto& value) {
        return value.isAddress<uint32_t>(address);
    });
    if (iter != end()) {
        index = iter - begin();
        return true;
    }
    return false;
}

bool instruction_container::findMnemonicIndex(ud_mnemonic_code mnemonic, size_t& index) const {
    auto iter = std::find_if(begin(), end(), [mnemonic](const auto& value) {
        return value.isMnemonic(mnemonic);
    });
    if (iter != end()) {
        index = iter - begin();
        return true;
    }
    return false;
}

bool instruction_container::findIndexByRegisterBase(ud_type base, size_t& index, ud_instruction& instruction) {
    auto iter = std::find_if(begin(), end(), [base, &instruction](const auto& value) {
        if (value.isOperandType(0, UD_OP_REG) && value.isOperandBase(0, base)) {
            instruction = value;
            return true;
        }
        return false;
    });
    if (iter != end()) {
        index = iter - begin();
        return true;
    }
    return false;
}

bool instruction_container::findIndexByMemoryBase(ud_type base, size_t operand, size_t& index, ud_instruction& instruction) {
    auto iter = std::find_if(begin(), end(), [base, operand, &instruction](const auto& value) {
        if (value.isOperandType(operand, UD_OP_MEM) && value.isOperandBase(operand, base)) {
            instruction = value;
            return true;
        }
        return false;
    });
    if (iter != end()) {
        index = iter - begin();
        return true;
    }
    return false;
}

bool instruction_container::findIndex(size_t& index, instruction_container_base::predicate_function predicate) const {
    auto iter = std::find_if(begin(), end(), predicate);
    if (iter != end()) {
        index = iter - begin();
        return true;
    }
    return false;
}
