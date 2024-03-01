#ifndef INSTRUCTION_CONTAINER_BRANCH_EVALUATOR_HPP_
#define INSTRUCTION_CONTAINER_BRANCH_EVALUATOR_HPP_

#include "instruction_container_deobfuscator.hpp"

class instruction_container_branch_evaluator : public instruction_container_deobfuscator
{
public:
	bool try_evaluate_branch(ud_instruction& instruction);
	bool try_evaluate_branch_simple();
	
private:
	bool evaluate_branch(ud_mnemonic_code mnemonic, bool* jump_condition);
	bool evaluate_conditional_jump(ud_mnemonic_code mnemonic, uint32_t flags);
	
	bool find_condition_start(std::size_t& index, uint32_t& product);

private:
	bool evaluating_branch;
};

#endif