#ifndef INSTRUCTION_CONTAINER_HPP_
#define INSTRUCTION_CONTAINER_HPP_

#include "instruction_container_branch_evaluator.hpp"

class wild_context;

class instruction_container : public instruction_container_branch_evaluator
{
public:
	bool decode_assembly(ud_instruction& instruction);
	
	void print_assembly(FILE* file = nullptr);
	void print_syntax(wild_context& context, ud_instruction& instruction, uint32_t handler_offset, FILE* file = nullptr);
	
public:
	void update_indexes();

public:
	bool has_address(uint32_t address) const;
	
	bool find_address_index(uint32_t address, std::size_t& index) const;
	bool find_mnemonic_index(ud_mnemonic_code mnemonic, std::size_t& index) const;
	
	bool find_index_by_register_base(ud_type base, std::size_t& index, ud_instruction& instruction);
	bool find_index_by_memory_base(ud_type base, std::size_t operand, std::size_t& index, ud_instruction& instruction);

private:
	bool find_index(size_type& index, predicate_function predicate) const;
	bool find(const_iterator& iter, size_type& index, predicate_function predicate) const;
};

#endif