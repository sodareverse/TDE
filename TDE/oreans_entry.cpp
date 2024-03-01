#include "oreans_entry.hpp"

#include <bytes.hpp>

#define VM_ENTRANCE_BUFFER_SIZE 512

bool oreans_entry::try_devirtualize(uint32_t vm_function, uint32_t vm_entry)
{
	unsigned char vm_entrance_buffer[VM_ENTRANCE_BUFFER_SIZE];
	get_many_bytes(vm_entry, vm_entrance_buffer, sizeof(vm_entrance_buffer));

	instruction_container vm_entrance;
	this->decode_vm_entrance(vm_entrance_buffer, vm_entry, vm_entrance);
		
	if (vm_entrance.size() == 2 &&
		vm_entrance.at(0).is_mnemonic(UD_Ipush) && vm_entrance.at(0).is_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD) &&
		vm_entrance.at(1).is_mnemonic(UD_Ijmp) && vm_entrance.at(1).is_operand_type(0, UD_OP_JIMM, UD_SIZE_DWORD))
	{
		if (this->vm_risc.is_signature(vm_entrance))
			return this->vm_risc.devirtualize(vm_function, vm_entry, vm_entrance);
		else if (this->vm_cisc.is_signature(vm_entrance))
			return this->vm_cisc.devirtualize(vm_function, vm_entry, vm_entrance);
	}	
	else if (vm_entrance.size() == 3 &&
		vm_entrance.at(0).is_mnemonic(UD_Ipush) && vm_entrance.at(0).is_operand_type(0, UD_OP_IMM) &&
		vm_entrance.at(1).is_mnemonic(UD_Ipush) && vm_entrance.at(1).is_operand_type(0, UD_OP_IMM) && 
		vm_entrance.at(2).is_mnemonic(UD_Ijmp) && vm_entrance.at(2).is_operand_type(0, UD_OP_JIMM))
	{
		qstrvec_t virtual_machines;
		virtual_machines.push_back(qstring("TIGER"));
		virtual_machines.push_back(qstring("FISH"));
		virtual_machines.push_back(qstring("PUMA"));
		virtual_machines.push_back(qstring("SHARK"));
		
		static int32_t vm_type_selection = 0;

		return this->show_virtual_machine_dialog(vm_function, vm_entry, vm_entrance, virtual_machines, vm_type_selection);
	}
	else
	{
		qstrvec_t virtual_machines;
		virtual_machines.push_back(qstring("TIGER"));
		virtual_machines.push_back(qstring("FISH"));
		virtual_machines.push_back(qstring("PUMA"));
		virtual_machines.push_back(qstring("SHARK"));
		virtual_machines.push_back(qstring("DOLPHIN"));
		virtual_machines.push_back(qstring("EAGLE"));

		static int32_t vm_type_selection = 0;
		
		return this->show_virtual_machine_dialog(vm_function, vm_entry, vm_entrance, virtual_machines, vm_type_selection);
	}

	return false;
}

bool oreans_entry::show_virtual_machine_dialog(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions, qstrvec_t& virtual_machines, int32_t& vm_type_selection)
{
	if (AskUsingForm_c("Select Virtual Machine\nAuto-analysis failed to determine VM-type for address %M.\n<Please specify VM architecture:b:0:::>",
		reinterpret_cast<ea_t*>(&vm_function), &virtual_machines, &vm_type_selection) == ASKBTN_YES)
	{
		switch (vm_type_selection)
		{
		case 0:
			msg("[CodeDevirtualizer] TIGER machine identified by user.\n");
			return this->vm_tiger.devirtualize(vm_function, vm_entry, vm_instructions);
				
		case 1:
			msg("[CodeDevirtualizer] FISH machine identified by user.\n");
			return this->vm_fish.devirtualize(vm_function, vm_entry, vm_instructions);

		case 2:
			msg("[CodeDevirtualizer] PUMA machine identified by user.\n");
			return this->vm_puma.devirtualize(vm_function, vm_entry, vm_instructions);

		case 3:
			msg("[CodeDevirtualizer] SHARK machine identified by user.\n");
			return this->vm_shark.devirtualize(vm_function, vm_entry, vm_instructions);
			
		case 4:
			msg("[CodeDevirtualizer] DOLPHIN machine identified by user.\n");
			return this->vm_dolphin.devirtualize(vm_function, vm_entry, vm_instructions);

		case 5:
			msg("[CodeDevirtualizer] EAGLE machine identified by user.\n");
			return this->vm_eagle.devirtualize(vm_function, vm_entry, vm_instructions);
				
		default:
			break;
		}
	}
	else
	{
		msg("[CodeDevirtualizer] No virtual machine selected.\n");
	}

	return false;
}

bool oreans_entry::decode_vm_entrance(uint8_t* buffer, uint32_t vm_entry, instruction_container& vm_entrance)
{
	ud_instruction instruction(vm_entry);
	instruction.set_input(buffer, VM_ENTRANCE_BUFFER_SIZE);

	do
	{
		if (!vm_entrance.decode_assembly(instruction))
			return false;
			
		if (instruction.is_mnemonic_jcc())
		{
			if (instruction.is_operand_type_not(0, UD_OP_JIMM) || instruction.has_operand_data(0))
			{
	//			if (this->try_evaluate_branch(vm_entrance, instruction, vm_entry + vm_offset))
	//				vm_offset += instruction.operands[0].data.dword;
			}
		}
	}
	while (instruction.is_mnemonic_not(UD_Ijmp));

	vm_entrance.deobfuscate();
	return true;
}