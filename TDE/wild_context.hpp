#ifndef WILD_CONTEXT_HPP_
#define WILD_CONTEXT_HPP_

#include "segment_manager.hpp"
#include "instruction_container.hpp"

#include "wild_context_keys.hpp"
#include "wild_opcode_label_manager.hpp"

#include <map>

class wild_context : public segment_manager, public wild_context_keys, public wild_opcode_label_manager
{
public:
	virtual void clear();
	
	void set_initial_parameters(uint32_t virtual_opcode, uint32_t handler_offset);
	void prepare_initial_parameters();	

public:
	bool is_key_access_instruction(ud_instruction& instruction, bool allow_mov);
	bool is_opcode_access_instruction(ud_instruction& instruction);

public:
	ud_type get_vm_register(uint16_t id);
	ud_type get_vm_high_byte_register(uint16_t id);
	bool set_vm_register(uint16_t id, ud_type type);
	
	ud_mnemonic_code get_mnemonic(uint8_t id);
	bool set_mnemonic(uint8_t id, ud_mnemonic_code mnemonic);

	ud_mnemonic_code get_jcc_mnemonic(uint8_t id);
	bool set_jcc_mnemonic(uint8_t id, ud_mnemonic_code mnemonic);

public:
	bool decode_zero_data(uint32_t vm_entrance);
	
private:
	bool parse_zero_data(instruction_container& instructions);

	bool parse_image_base(instruction_container& instructions, std::size_t& index);
	bool parse_vm_context(instruction_container& instructions, std::size_t& index);
	bool parse_vm_imagebase_offset(instruction_container& instructions, std::size_t& index);
	bool parse_vm_imagebase_preferred_offset(instruction_container& instructions, std::size_t& index);
	bool parse_vm_imagebase_preferred(instruction_container& instructions, std::size_t& index);
	bool parse_vm_opcode_offset(instruction_container& instructions, std::size_t& index);
	bool parse_vm_handler_table(instruction_container& instructions, std::size_t& index);
	bool parse_vm_handler_table_offset(instruction_container& instructions, std::size_t& index);
	bool parse_vm_handler_count(instruction_container& instructions, std::size_t& index);

public:
	bool initialized_crypto_offset;
	uint16_t crypto_offset;

	uint32_t vm_imagebase;
	uint32_t vm_context;					// Unknown 1 (00416D4E)
	uint32_t vm_imagebase_offset;			// Unknown 2 (00000075)
	uint32_t vm_imagebase_preferred_offset;	// Unknown 3 (0000003F)
	uint32_t vm_imagebase_preferred;		// Unknown 4 (00400000)
	uint32_t vm_opcode_offset;				// Unknown 5 (00000008)
	uint32_t vm_handler_table;				// Unknown 6 (004346A1)
	uint32_t vm_handler_table_offset;		// Unknown 7 (0000004F)
	uint32_t vm_handler_count;				// Unknown 8 (00000086)
	
	bool initialized_jcc_types;
	bool initialized_eflags_types;
	
	uint32_t step_params[5];
	
	/* ... */
	uint32_t initial_virtual_opcode;
	uint32_t current_virtual_opcode;
	
	uint32_t initial_handler_offset;
	uint32_t current_handler_offset;

	/* ... */
	int32_t current_register_type;
	uint16_t register_addr1_id;
	uint16_t register_addr2_id;

private:
	std::map<uint16_t, ud_type> register_types;
	std::map<uint8_t, ud_mnemonic_code> mnemonic_types;
	std::map<uint8_t, ud_mnemonic_code> jcc_mnemonic_types;
};

#endif