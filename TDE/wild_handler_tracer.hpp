#ifndef WILD_HANDLER_TRACER_HPP_
#define WILD_HANDLER_TRACER_HPP_

#include "oreans_base.hpp"
#include "wild_context.hpp"

#include <stack>

class wild_handler_tracer : public oreans_base
{
	template <typename T>
	class clearable_stack : public std::stack<T>
	{
	public:
		void clear()
		{
			this->c.clear();
		}
	};

protected:
	wild_handler_tracer(wild_context& context);

protected:
	void trace(uint32_t vm_handler, uint32_t& compares, instruction_container& instructions);

private:
	void trace_cmp(uint32_t& compares);
	bool trace_jmp(instruction_container& instructions, ud_instruction& instruction);
	bool trace_ret(instruction_container& instructions, ud_instruction& instruction);
	bool trace_jcc(instruction_container& instructions, ud_instruction& instruction, uint32_t& compares);
	
	void trace_branch_compares(instruction_container& instructions);
	void trace_branch_obfuscation(ud_instruction& instruction);
	bool trace_branch_obfuscation_continue(ud_instruction& instruction);

	bool trace_jcc_back(instruction_container& instructions, ud_instruction& instruction);

	bool is_branch_obfuscation(instruction_container& instructions);
	
protected:
	wild_context& context;

private:
	bool tracing_branch_obfuscation;

	uint32_t branch_continue;
	uint32_t branch_remaining;

	clearable_stack<uint32_t> jcc_branches;
};

#endif