#include "oreans_entry.hpp"
#include <bytes.hpp>

#define VM_ENTRANCE_BUFFER_SIZE 512

bool OreansEntry::tryDevirtualize(uint32_t vmFunction, uint32_t vmEntry) {
    unsigned char vmEntranceBuffer[VM_ENTRANCE_BUFFER_SIZE];
    get_many_bytes(vmEntry, vmEntranceBuffer, sizeof(vmEntranceBuffer));

    InstructionContainer vmEntrance;
    if (!decodeVmEntrance(vmEntranceBuffer, vmEntry, vmEntrance))
        return false;

    if (vmEntrance.size() == 2 &&
        vmEntrance.at(0).isPushImmediate() && vmEntrance.at(0).isOperandType(0, UD_OP_IMM, UD_SIZE_DWORD) &&
        vmEntrance.at(1).isJumpImmediate()) {
        if (vmRisc.isSignature(vmEntrance))
            return vmRisc.devirtualize(vmFunction, vmEntry, vmEntrance);
        else if (vmCisc.isSignature(vmEntrance))
            return vmCisc.devirtualize(vmFunction, vmEntry, vmEntrance);
    } else if (vmEntrance.size() == 3 &&
               vmEntrance.at(0).isPushImmediate() && vmEntrance.at(0).isOperandType(0, UD_OP_IMM) &&
               vmEntrance.at(1).isPushImmediate() && vmEntrance.at(1).isOperandType(0, UD_OP_IMM) &&
               vmEntrance.at(2).isJumpImmediate()) {
        qstrvec_t virtualMachines = {"TIGER", "FISH", "PUMA", "SHARK"};
        static int32_t vmTypeSelection = 0;
        return showVirtualMachineDialog(vmFunction, vmEntry, vmEntrance, virtualMachines, vmTypeSelection);
    } else {
        qstrvec_t virtualMachines = {"TIGER", "FISH", "PUMA", "SHARK", "DOLPHIN", "EAGLE"};
        static int32_t vmTypeSelection = 0;
        return showVirtualMachineDialog(vmFunction, vmEntry, vmEntrance, virtualMachines, vmTypeSelection);
    }
    return false;
}

bool OreansEntry::showVirtualMachineDialog(uint32_t vmFunction, uint32_t vmEntry, InstructionContainer& vmInstructions, qstrvec_t& virtualMachines, int32_t& vmTypeSelection) {
    if (AskUsingForm_c("Select Virtual Machine\nAuto-analysis failed to determine VM-type for address %M.\n<Please specify VM architecture:b:0:::>",
        reinterpret_cast<ea_t*>(&vmFunction), &virtualMachines, &vmTypeSelection) == ASKBTN_YES) {
        switch (vmTypeSelection) {
            case 0:
                msg("TIGER machine identified by user.\n");
                return vmTiger.devirtualize(vmFunction, vmEntry, vmInstructions);
            case 1:
                msg("FISH machine identified by user.\n");
                return vmFish.devirtualize(vmFunction, vmEntry, vmInstructions);
            case 2:
                msg("PUMA machine identified by user.\n");
                return vmPuma.devirtualize(vmFunction, vmEntry, vmInstructions);
            case 3:
                msg("SHARK machine identified by user.\n");
                return vmShark.devirtualize(vmFunction, vmEntry, vmInstructions);
            case 4:
                msg("DOLPHIN machine identified by user.\n");
                return vmDolphin.devirtualize(vmFunction, vmEntry, vmInstructions);
            case 5:
                msg("EAGLE machine identified by user.\n");
                return vmEagle.devirtualize(vmFunction, vmEntry, vmInstructions);
            default:
                break;
        }
    } else {
        msg("No virtual machine selected.\n");
    }
    return false;
}

bool OreansEntry::decodeVmEntrance(uint8_t* buffer, uint32_t vmEntry, InstructionContainer& vmEntrance) {
    ud_instruction instruction(vmEntry);
    instruction.setInput(buffer, VM_ENTRANCE_BUFFER_SIZE);

    do {
        if (!vmEntrance.decodeAssembly(instruction))
            return false;
        if (instruction.isMnemonicJumpConditional()) {
            if (instruction.isOperandTypeNot(0, UD_OP_JIMM) || instruction.hasOperandData(0)) {
                // if (tryEvaluateBranch(vmEntrance, instruction, vmEntry + vmOffset))
                //     vmOffset += instruction.operands[0].data.dword;
            }
        }
    } while (instruction.isMnemonicNot(UD_Ijmp));

    vmEntrance.deobfuscate();
    return true;
}
