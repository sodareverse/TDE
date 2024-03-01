#ifndef OREANS_ENTRY_HPP_
#define OREANS_ENTRY_HPP_

#include "instruction_container.hpp"

#include "cisc.hpp"
#include "risc.hpp"

#include "fish.hpp"
#include "tiger.hpp"
#include "dolphin.hpp"

#include "puma.hpp"
#include "shark.hpp"
#include "eagle.hpp"

#include <idp.hpp>

class oreans_entry
{
public:
	static oreans_entry& get()
	{
		static oreans_entry instance;
		return instance;
	}

public:
	bool try_devirtualize(uint32_t vm_function, uint32_t vm_entry);
	bool show_virtual_machine_dialog(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_instructions, qstrvec_t& virtual_machines, int32_t& vm_type_selection);

private:
	bool decode_vm_entrance(uint8_t* buffer, uint32_t vm_entry, instruction_container& vm_entrance);

private:
	cisc vm_cisc;
	risc vm_risc;

	fish vm_fish;
	tiger vm_tiger;
	dolphin vm_dolphin;

	puma vm_puma;
	shark vm_shark;
	eagle vm_eagle;
};

#endif