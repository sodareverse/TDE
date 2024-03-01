#include "instruction_container_branch_evaluator.hpp"
#include "instruction_emulator.hpp"

#include <idp.hpp>

bool instruction_container_branch_evaluator::try_evaluate_branch(ud_instruction& instruction)
{
	bool jump_condition = false;

	if (!this->evaluate_branch(instruction.mnemonic, &jump_condition))
		jump_condition = (askbuttons_c(NULL, NULL, NULL, ASKBTN_YES, "HIDECANCEL\nCould not evaluate jcc branch for mnemonic %04X at address %08X\nWould you like to follow the jump?", instruction.mnemonic, instruction.get_address<uint32_t>()) == ASKBTN_YES);

	return jump_condition;
}

bool instruction_container_branch_evaluator::try_evaluate_branch_simple()
{
	ud_instruction& instruction = this->at(this->size() - 2);

	if (instruction.is_mnemonic(UD_Icmp))
		return true;
	else if (instruction.is_mnemonic(UD_Itest))
		return true;
	else if (instruction.is_mnemonic(UD_Ior) &&
		instruction.is_operand_type(0, UD_OP_REG) &&
		instruction.is_operand_type(1, UD_OP_REG) &&
		instruction.is_operand_base(1, instruction, 0))
	{
		return true;
	}

	return false;
}

bool instruction_container_branch_evaluator::evaluate_branch(ud_mnemonic_code mnemonic, bool* jump_condition)
{
	if (this->empty())
		return false;

	this->evaluating_branch = true;
	
	ud_instruction& instruction = this->at(this->size() - 2);

	/*
		0: mov ___,___
		1: jcc _______
	*/
	if (instruction.is_mnemonic(UD_Imov))
	{
		this->evaluating_branch = false;
		return false;
	}
	/*
		0: cmp ___,___
		1: jcc _______
	*/
	else if (instruction.is_mnemonic(UD_Icmp))
	{
		this->evaluating_branch = false;
		return true;
	}
	/*
		0: test ___,___
		1: jcc ________
	*/
	else if (instruction.is_mnemonic(UD_Itest))
	{
		this->evaluating_branch = false;
		return true;
	}
	/*
		0: or reg1,reg1
		1: jcc ________
	*/
	else if (instruction.is_mnemonic(UD_Ior) &&
		instruction.is_operand_type(0, UD_OP_REG) &&
		instruction.is_operand_type(1, UD_OP_REG) &&
		instruction.is_operand_base(1, instruction, 0))
	{
		this->evaluating_branch = false;
		return true;
	}
	else
	{
		uint32_t imm_product = 0;
		std::size_t index = static_cast<std::size_t>(-1);

		if (this->find_condition_start(index, imm_product) || (this->deobfuscate(), this->find_condition_start(index, imm_product)))
		{
			uint32_t eflags = 0;

			for (std::size_t i = index + 1; i < this->size(); i++)
			{
				if (instruction.is_operand_type(0, UD_OP_REG))
				{
					instruction::emulate_eflags(this->at(i).mnemonic, this->at(i).get_base_size(0), this->at(i).get_operand_data(1), imm_product, &eflags);
					instruction::emulate(this->at(i).mnemonic, this->at(i).get_base_size(0), this->at(i).get_operand_data(1), &imm_product);
				}
				else
				{
					instruction::emulate_eflags(this->at(i).mnemonic, this->at(i).get_operand_size(0), this->at(i).get_operand_data(1), imm_product, &eflags);
					instruction::emulate(this->at(i).mnemonic, this->at(i).get_operand_size(0), this->at(i).get_operand_data(1), &imm_product);
				}
			}

			*jump_condition = this->evaluate_conditional_jump(mnemonic, eflags);
			this->evaluating_branch = false;
			return true;
		}
	}

	this->evaluating_branch = false;
	return false;
}

bool instruction_container_branch_evaluator::evaluate_conditional_jump(ud_mnemonic_code mnemonic, uint32_t flags)
{
	#define CARRY_FLAG(x)		(((x) >> 0) & 1)	// Carry bit = 0
	#define PARITY_FLAG(x)		(((x) >> 2) & 1)	// Parity bit = 2
	#define ZERO_FLAG(x)		(((x) >> 6) & 1)	// Zero bit = 6
	#define SIGN_FLAG(x)		(((x) >> 7) & 1)	// Sign bit = 7
	#define OVERFLOW_FLAG(x)	(((x) >> 11) & 1)	// Overflow bit = 11

	switch (mnemonic)
	{
	case UD_Ija:	/* Jump if above (alt: not below or equal): CF = 0 & ZF = 0 */
		return (CARRY_FLAG(flags) == 0 && ZERO_FLAG(flags) == 0);
	
	case UD_Ijae:	/* Jump if above or equal (alt: not carry, not below ): CF = 0 */
		return (CARRY_FLAG(flags) == 0);
	
	case UD_Ijb:	/* Jump if below (alt: carry, not above or equal): CF = 1 */
		return (CARRY_FLAG(flags) == 1);
	
	case UD_Ijbe:	/* Jump if below or equal (alt: not above): CF = 1 | ZF = 1 */
		return (CARRY_FLAG(flags) == 1 || ZERO_FLAG(flags) == 1);
	
	case UD_Ijz:	/* Jump if zero (alt: equal): ZF = 1 */
		return (ZERO_FLAG(flags) == 1);
	
	case UD_Ijnz:	/* Jump if not zero (alt: not equal): ZF = 0 */
		return (ZERO_FLAG(flags) == 0);
	
	case UD_Ijg:	/* Jump if greater (alt: not less or equal): SF = OF & ZF = 0 */
		return (SIGN_FLAG(flags) == OVERFLOW_FLAG(flags) && ZERO_FLAG(flags) == 0);
	
	case UD_Ijge:	/* Jump if greater or equal (alt: not less): SF = OF */
		return (SIGN_FLAG(flags) == OVERFLOW_FLAG(flags));
	
	case UD_Ijl:	/* Jump if less (alt: not greater or equal): SF <> OF */
		return (SIGN_FLAG(flags) != OVERFLOW_FLAG(flags));
	
	case UD_Ijle:	/* Jump if less or equal (alt: not greater): SF <> OF | ZF = 1 */
		return (SIGN_FLAG(flags) != OVERFLOW_FLAG(flags) || ZERO_FLAG(flags) == 1);
	
	case UD_Ijo:	/* Jump if overflow: OF = 1 */
		return (OVERFLOW_FLAG(flags) == 1);
	
	case UD_Ijno:	/* Jump if not overflow: OF = 0 */
		return (OVERFLOW_FLAG(flags) == 0);
	
	case UD_Ijp:	/* Jump if parity (alt: parity even): PF = 1 */
		return (PARITY_FLAG(flags) == 1);
	
	case UD_Ijnp:	/* Jump if not parity (alt: parity odd): PF = 0 */
		return (PARITY_FLAG(flags) == 0);
	
	case UD_Ijs:	/* Jump if sign: SF = 1 */
		return (SIGN_FLAG(flags) == 1);

	case UD_Ijns:	/* Jump if not sign: SF = 0 */
		return (SIGN_FLAG(flags) == 0);
	
	case UD_Ijcxz:
	case UD_Ijecxz:
	case UD_Ijrcxz:
		/* ... */

	default:
		printf("Invalid mnemonic to perform conditional jump evaluation.\n");
		return false;
	}

	return true;
}

bool instruction_container_branch_evaluator::find_condition_start(std::size_t& index, uint32_t& product)
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		if (!this->at(i).compare_mnemonic(true, true, true))
			return false;
		
		if (this->at(i).compare_mnemonic(true, false, true))
		{
			if (this->at(i).is_operand_type_not(0, { UD_OP_REG, UD_OP_MEM }) ||
				this->at(i).is_operand_base_not(0, this->back(), 0) ||
				this->at(i).is_operand_index_not(0, this->back(), 0) ||
				this->at(i).is_operand_scale_not(0, this->back(), 0) ||
				this->at(i).is_operand_data_not(0, this->back(), 0) ||
				this->at(i).is_operand_type_not(1, UD_OP_IMM))
			{
				return false;
			}

			if (this->at(i).compare_mnemonic(true, false, false))
			{
				index = i;
				product = this->at(i).get_operand_data(1);
				return true;
			}
		}

		if (this->at(i).compare_mnemonic(false, true, false))
		{
			if (this->at(i).is_operand_type_not(0, { UD_OP_REG, UD_OP_MEM }) ||
				this->at(i).is_operand_base_not(0, this->back(), 0) ||
				this->at(i).is_operand_index_not(0, this->back(), 0) ||
				this->at(i).is_operand_scale_not(0, this->back(), 0) ||
				this->at(i).is_operand_data_not(0, this->back(), 0))
			{
				return false;
			}
		}
	}

	return true;
}