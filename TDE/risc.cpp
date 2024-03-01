#include "risc.hpp"

#include <idp.hpp>
#include <allins.hpp>

#define RISC_VM_SIGNATURE_BUFFER_SIZE 512

bool risc::is_signature(instruction_container& vm_entrance)
{
	decode_insn(vm_entrance.at(1).get_address<uint32_t>());

	if (cmd.itype == NN_jmp && cmd.Operands[0].addr != 0)
	{
		unsigned char risc_vm_signature_buffer[RISC_VM_SIGNATURE_BUFFER_SIZE];
		get_many_bytes(cmd.Operands[0].addr, risc_vm_signature_buffer, sizeof(risc_vm_signature_buffer));
			
		ud_instruction instruction(cmd.Operands[0].addr);
		instruction.set_input(risc_vm_signature_buffer, sizeof(risc_vm_signature_buffer));

		instruction_container instructions;

		do
		{
			if (!instructions.decode_assembly(instruction))
				return false;

			if (instruction.is_mnemonic(UD_Inop))
				msg("[CodeDevirtualizer] RISC machine identified. Scanning type...\n");
			else if (instruction.is_mnemonic(UD_Icall))
			{
				/* 0: call unknown ptr [mem] */
				if (instruction.is_operand_type(0, UD_OP_MEM))
				{
					msg("[CodeDevirtualizer] RISC machine identified as RISC-64.\n");
					return true;
				}
				/* 0: call reg */
				else if (instruction.is_operand_type(0, UD_OP_REG))
				{
					msg("[CodeDevirtualizer] RISC machine identified as RISC-128.\n");
					return true;
				}
			}
		}
		while (instruction.is_mnemonic_not(UD_Ijmp));
	}
	
	return false;
}

bool risc::devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_entrance)
{
	msg("[CodeDevirtualizer] RISC machines are currently not supported.\n");
	return false;
}