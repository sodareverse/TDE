#include "instruction_container_deobfuscator.hpp"
#include "instruction_emulator.hpp"

void instruction_container_deobfuscator::deobfuscate()
{
	uint32_t pre_deobfuscation_size = 0;

	do
	{
		pre_deobfuscation_size = this->size();

		this->deobfuscate_push();
		this->deobfuscate_pop();
		this->deobfuscate_stack();
		this->deobfuscate_xchg_v1();
		this->deobfuscate_mov_v1();
		this->deobfuscate_xchg_v2();
		this->deobfuscate_arithmetics();
		this->deobfuscate_offset();
		this->deobfuscate_generated_memory();
		this->deobfuscate_generated_register();
		this->deobfuscate_neg();
		
		if (pre_deobfuscation_size == this->size())
			this->deobfuscate_mov_v2();
	}
	while (pre_deobfuscation_size != this->size());
}

void instruction_container_deobfuscator::deobfuscate_wild()
{
	uint32_t pre_deobfuscation_size = 0;

	do
	{
		pre_deobfuscation_size = this->size();
		
		this->deobfuscate_push();
		this->deobfuscate_pop();
		this->deobfuscate_stack();
		this->deobfuscate_xchg_v1();
		this->deobfuscate_mov_v1();
		this->deobfuscate_xchg_v2();
		this->deobfuscate_arithmetics();
		this->deobfuscate_offset();
		this->deobfuscate_generated_memory();
		this->deobfuscate_generated_register();
		this->deobfuscate_neg();
		
		if (pre_deobfuscation_size == this->size())
		{
			this->deobfuscate_mov_v2();
			
			if (pre_deobfuscation_size == this->size())
			{
				this->deobfuscate_fillers();

				//if (pre_deobfuscation_size == instructions.size())
				//	this->deobfuscate_new_types(instructions);
			}
		}
	}
	while (pre_deobfuscation_size != this->size());
}

void instruction_container_deobfuscator::deobfuscate_push()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: sub esp,02/04
			1: mov (d)word ptr [esp],reg
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Isub) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_base(0, UD_R_ESP) &&
			this->at(i).is_operand_type(1, UD_OP_IMM) &&
			this->at(i).is_operand_data(1, { 2, 4 }) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM, { UD_SIZE_WORD, UD_SIZE_DWORD }) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			this->at(i + 1).has_operand_data_not(0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG))
		{
			/* 1: mov (d)word ptr [esp],(e)sp */
			if (this->at(i + 1).is_operand_base(1, { UD_R_SP, UD_R_ESP }))
			{
				/* 2: add unknown ptr [esp],02/04 */
				if (this->bounds(i, 2) &&
					this->at(i + 2).is_mnemonic(UD_Iadd) &&
					this->at(i + 2).is_operand_type(0, UD_OP_MEM) &&
					this->at(i + 2).is_operand_base(0, UD_R_ESP) &&
					this->at(i + 2).has_operand_index_not(0) &&
					this->at(i + 2).has_operand_scale_not(0) &&
					this->at(i + 2).has_operand_data_not(0) &&
					this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&
					this->at(i + 2).is_operand_data(1, { 2, 4 }))
				{
					/* 0: push esp */
					this->at(i).set_mnemonic(UD_Ipush);
					this->at(i).set_prefixes(this->at(i + 1));
					this->at(i).set_operand(0, this->at(i + 1), 1);
					this->at(i).set_operand_null(1);

					this->remove(i + 1, 2);
				}
			}
			else
			{
				/* 0: push reg */
				this->at(i).set_mnemonic(UD_Ipush);
				this->at(i).set_prefixes(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i + 1), 1);
				this->at(i).set_operand_null(1);
		
				this->remove(i + 1);
			}
		}
	
		/*
			0: push reg/imm
			1: mov (d)word ptr [esp],reg
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_IMM }) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM, { UD_SIZE_WORD, UD_SIZE_DWORD }) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			this->at(i + 1).has_operand_data_not(0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG))
		{
			/* 1: mov (d)word ptr [esp],(e)sp */
			if (this->at(i + 1).is_operand_base(1, { UD_R_SP, UD_R_ESP }))
			{
				/* 2: add unknown ptr [esp],02/04 */
				if (this->bounds(i, 2) &&
					this->at(i + 2).is_mnemonic(UD_Iadd) &&
					this->at(i + 2).is_operand_type(0, UD_OP_MEM) &&
					this->at(i + 2).is_operand_base(0, UD_R_ESP) &&
					this->at(i + 2).has_operand_index_not(0) &&
					this->at(i + 2).has_operand_scale_not(0) &&
					this->at(i + 2).has_operand_data_not(0) &&
					this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&
					this->at(i + 2).is_operand_data(1, { 2, 4 }))
				{
					/* 0: push esp */
					this->at(i).set_mnemonic(UD_Ipush);
					this->at(i).set_prefixes(this->at(i + 1));
					this->at(i).set_operand(0, this->at(i + 1), 1);

					this->remove(i + 1, 2);
				}
			}
			else
			{
				/* 0: push reg */
				this->at(i).set_mnemonic(UD_Ipush);
				this->at(i).set_prefixes(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i + 1), 1);
		
				this->remove(i + 1);
			}
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_pop()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: mov reg,(d)word ptr [esp]
			1: add esp,02/04
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Imov) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_base_not(0, { UD_R_SP, UD_R_ESP }) &&
			this->at(i).is_operand_type(1, UD_OP_MEM, { UD_SIZE_WORD, UD_SIZE_DWORD }) &&
			this->at(i).is_operand_base(1, UD_R_ESP) &&
			this->at(i).has_operand_index_not(1) &&
			this->at(i).has_operand_scale_not(1) &&
			this->at(i).has_operand_data_not(1) &&
			
			this->at(i + 1).is_mnemonic(UD_Iadd) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&
			this->at(i + 1).is_operand_data(1, { 2, 4 }))
		{
			/* 0: pop reg */
			this->at(i).set_mnemonic(UD_Ipop);
			this->at(i).set_operand_null(1);
		
			this->remove(i + 1);
		}

		/* 0: mov (e)sp,(d)word ptr [esp] */
		if (this->bounds(i) &&
			this->at(i).is_mnemonic(UD_Imov) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_base(0, { UD_R_SP, UD_R_ESP }) &&
			this->at(i).is_operand_type(1, UD_OP_MEM, { UD_SIZE_WORD, UD_SIZE_DWORD }) &&
			this->at(i).is_operand_base(1, UD_R_ESP) &&
			this->at(i).has_operand_index_not(1) &&
			this->at(i).has_operand_scale_not(1) &&
			this->at(i).has_operand_data_not(1))
		{
			/* 0: pop (e)sp */
			this->at(i).set_mnemonic(UD_Ipop);
			this->at(i).set_operand_null(1);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_stack()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: push (reg != esp)
			1: mov reg,esp
			2: add reg,04
			3: add/sub reg,imm
			4: xchg reg/(d)word ptr [esp],reg/(d)word ptr [esp]
			5: pop esp
		*/
		if (this->bounds(i, 5) &&			
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_base_not(0, UD_R_ESP) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 1).is_operand_base(1, UD_R_ESP) &&
			
			this->at(i + 2).is_mnemonic(UD_Iadd) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&
			this->at(i + 2).is_operand_data(1, 4) &&
			
			this->at(i + 3).is_mnemonic({ UD_Iadd, UD_Isub }) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 3).is_operand_type(1, UD_OP_IMM) &&

			this->at(i + 4).is_mnemonic(UD_Ixchg) &&
			((this->at(i + 4).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) && 
			this->at(i + 4).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 4).has_operand_index_not(0) &&
			this->at(i + 4).has_operand_scale_not(0) &&
			this->at(i + 4).has_operand_data_not(0) &&
			this->at(i + 4).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(1, this->at(i), 0)) ||
			(this->at(i + 4).is_operand_type(0, UD_OP_REG) && 
			this->at(i + 4).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 4).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			this->at(i + 4).is_operand_base(1, UD_R_ESP) &&
			this->at(i + 4).has_operand_index_not(1) &&
			this->at(i + 4).has_operand_scale_not(1) &&
			this->at(i + 4).has_operand_data_not(1))) &&

			this->at(i + 5).is_mnemonic(UD_Ipop) &&
			this->at(i + 5).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 5).is_operand_base(0, UD_R_ESP))
		{
			/* 0: add/sub esp,imm */
			this->at(i).set_mnemonic(this->at(i + 3));
			this->at(i).set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
			this->at(i).set_operand_base(0, UD_R_ESP);
			this->at(i).set_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD);
			this->at(i).set_operand_data(1, this->at(i + 3), 1);

			this->remove(i + 1, 5);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_xchg_v1()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: xor x1,x2
			1: xor x2,x1
			2: xor x1,x2
		*/
		if (this->bounds(i, 2) &&
			this->at(i).is_mnemonic(UD_Ixor) &&

			this->at(i + 1).is_mnemonic(UD_Ixor) &&
			this->at(i + 1).is_operand(0, this->at(i), 1) &&
			this->at(i + 1).is_operand(1, this->at(i), 0) &&

			this->at(i + 2).is_mnemonic(UD_Ixor) &&
			this->at(i + 2).is_operand(0, this->at(i + 1), 1) &&
			this->at(i + 2).is_operand(1, this->at(i + 1), 0))
		{
			/* 0: xchg x1,x2 */
			this->at(i).set_mnemonic(UD_Ixchg);
			this->at(i).set_operand(0, this->at(i + 1), 0);
			this->at(i).set_operand(1, this->at(i + 2), 0);
			
			this->remove(i + 1, 2);
		}

		/*
			0: push reg
			1: mov reg,dword ptr [esp+4]
			2: pop dword ptr [esp]
		*/
		if (this->bounds(i, 2) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_base_not(0, UD_R_ESP) &&

			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
			this->at(i + 1).is_operand_base(1, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(1) &&
			this->at(i + 1).has_operand_scale_not(1) &&
			this->at(i + 1).is_operand_data(1, 4) &&

			this->at(i + 2).is_mnemonic(UD_Ipop) &&
			this->at(i + 2).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			this->at(i + 2).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 2).has_operand_index_not(0) &&
			this->at(i + 2).has_operand_scale_not(0) &&
			this->at(i + 2).has_operand_data_not(0))
		{
			/* 0: xchg reg,dword ptr [esp] */
			this->at(i).set_mnemonic(UD_Ixchg);
			this->at(i).set_operand(1, this->at(i + 2), 0);

			this->remove(i + 1, 2);
		}

		/*
			0: push reg1
			1: mov reg1,x2
			2: mov x2,x3
			3: mov x3,reg1
			4: pop reg1
		*/
		if (this->bounds(i, 4) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&

			this->at(i + 2).is_mnemonic(UD_Imov) &&
			this->at(i + 2).is_operand(0, this->at(i + 1), 1) &&

			this->at(i + 3).is_mnemonic(UD_Imov) &&
			this->at(i + 3).is_operand(0, this->at(i + 2), 1) &&
			this->at(i + 3).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 3).is_operand(1, this->at(i + 1), 0) &&

			this->at(i + 4).is_mnemonic(UD_Ipop) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i), 0))
		{
			/* 0: xchg x2,x3 */
			this->at(i).set_mnemonic(UD_Ixchg);
			this->at(i).set_prefixes(this->at(i + 3));
			this->at(i).set_operand(0, this->at(i + 3), 0);
			this->at(i).set_operand(1, this->at(i + 2), 0);
			
			if (this->at(i).is_operand_type(0, UD_OP_MEM) && this->at(i).is_operand_base(0, UD_R_ESP))
				this->at(i).dec_operand_data<uint32_t>(0, this->at(i + 4).is_operand_base_size(0, UD_SIZE_DWORD) ? 4 : 2);
			
			if (this->at(i).is_operand_type(1, UD_OP_MEM) && this->at(i).is_operand_base(1, UD_R_ESP))
				this->at(i).dec_operand_data<uint32_t>(1, this->at(i + 4).is_operand_base_size(0, UD_SIZE_DWORD) ? 4 : 2);
			
			this->remove(i + 1, 4);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_mov_v1()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: push x1
			1: pop x2
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i + 1).is_mnemonic(UD_Ipop) &&
			
			((this->at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG, UD_SIZE_DWORD)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_REG, UD_SIZE_WORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_WORD)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_MEM, UD_SIZE_WORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG, UD_SIZE_WORD)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG)) ||
			
			(this->at(i).is_operand_type(0, UD_OP_IMM, UD_SIZE_WORD) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG))))
		{
			/* 0: mov x2,x1 */
			this->at(i).set_mnemonic(UD_Imov);
			this->at(i).set_operand(1, this->at(i), 0);
			this->at(i).set_operand(0, this->at(i + 1), 0);
			
			this->remove(i + 1);
		}

		/*
			0: push x1
			1: sub|add|xor unknown ptr [esp],imm
			2: pop x2
			3: add|sub|xor x2,imm
		*/
		if (this->bounds(i, 3) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&

			((this->at(i + 1).is_mnemonic(UD_Isub) && this->at(i + 3).is_mnemonic(UD_Iadd)) ||
			(this->at(i + 1).is_mnemonic(UD_Iadd) && this->at(i + 3).is_mnemonic(UD_Isub)) ||
			(this->at(i + 1).is_mnemonic(UD_Ixor) && this->at(i + 3).is_mnemonic(UD_Ixor))) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			this->at(i + 1).has_operand_data_not(0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&
			
			this->at(i + 2).is_mnemonic(UD_Ipop) &&
			this->at(i + 2).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&

			this->at(i + 3).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 3).is_operand(0, this->at(i + 2), 0) &&
			this->at(i + 3).is_operand_type(1, UD_OP_IMM) &&
			this->at(i + 3).is_operand_data(1, this->at(i + 1), 1))
		{
			/* 0: mov x2,x1 */
			this->at(i).set_mnemonic(UD_Imov);
			this->at(i).set_operand(1, this->at(i), 0);
			this->at(i).set_operand(0, this->at(i + 2), 0);

			this->remove(i + 1, 3);
		}
		
		/*
			0: push reg
			1: mov reg,imm
			2: mov x2,imm
			3: ___ x2,reg
			4: pop reg
		*/
		if (this->bounds(i, 4) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&

			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&

			this->at(i + 2).is_mnemonic(UD_Imov) &&
			this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&

			this->at(i + 3).compare_mnemonic(true, false, true) &&
			this->at(i + 3).is_operand_sib(0, this->at(i + 2), 0) &&
			this->at(i + 3).is_operand_data(0, this->at(i + 2), 0) &&
			this->at(i + 3).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 3).is_operand(1, this->at(i + 1), 0) &&

			this->at(i + 4).is_mnemonic(UD_Ipop) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i), 0))
		{
			/* 0: mov x2,imm */
			uint32_t imm_product = this->at(i + 2).get_operand_data<uint32_t>(1);

			if (this->at(i + 3).is_operand_type(0, UD_OP_REG))
				instruction::emulate(this->at(i + 3).get_mnemonic(), this->at(i + 3).get_base_size(0), this->at(i + 1).get_operand_data(1), &imm_product);
			else if (this->at(i + 3).is_operand_type(0, UD_OP_MEM))
			{
				/* 3: ___ [esp+xx],x1 */
				if (this->at(i + 3).is_operand_base(0, UD_R_ESP))
					this->at(i + 3).dec_operand_data<uint32_t>(0, this->at(i).is_operand_base_size(0, UD_SIZE_DWORD) ? 4 : 2);
				
				instruction::emulate(this->at(i + 3).get_mnemonic(), this->at(i + 3).get_operand_size(0), this->at(i + 1).get_operand_data(1), &imm_product);
			}

			this->at(i).set_mnemonic(UD_Imov);
			this->at(i).set_prefixes(this->at(i + 3));
			this->at(i).set_operand(0, this->at(i + 3), 0);
			this->at(i).set_operand(1, this->at(i + 1), 1);
			this->at(i).set_operand_data(1, imm_product);

			this->remove(i + 1, 4);
		}

		/*
			0: push reg
			1: mov reg,imm
			2: mov x,imm
			3: ___ x,reg
			4: ___ x,imm
			5: pop reg
		*/
		if (this->bounds(i, 5) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&

			this->at(i + 2).is_mnemonic(UD_Imov) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&
			
			this->at(i + 3).compare_mnemonic(true, false, true) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base_not(0, this->at(i + 1), 0) &&
			this->at(i + 3).is_operand_base(0, this->at(i + 2), 0) &&
			this->at(i + 3).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(1, this->at(i + 1), 0) &&
			
			this->at(i + 4).compare_mnemonic(true, false, true) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i + 3), 0) &&
			this->at(i + 4).is_operand_type(1, { UD_OP_IMM, UD_OP_CONST }) &&

			this->at(i + 5).is_mnemonic(UD_Ipop) &&
			this->at(i + 5).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 5).is_operand_base(0, this->at(i), 0))
		{
			/* 0: mov reg2,imm */
			uint32_t imm_product = this->at(i + 2).get_operand_data<uint32_t>(1);
			
			instruction::emulate(this->at(i + 3).get_mnemonic(), this->at(i + 3).get_base_size(0), this->at(i + 1).get_operand_data(1), &imm_product);
			instruction::emulate(this->at(i + 4).get_mnemonic(), this->at(i + 4).get_base_size(0), this->at(i + 4).get_operand_data(1), &imm_product);

			this->at(i).set_mnemonic(UD_Imov);
			this->at(i).set_prefixes(this->at(i + 3));
			this->at(i).set_operand(0, this->at(i + 3), 0);
			this->at(i).set_operand(1, this->at(i + 1), 1);
			this->at(i).set_operand_data(1, imm_product);

			this->remove(i + 1, 5);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_xchg_v2()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: xchg x1,x2
			1: ___ ___,___
			2: xchg x1,x2
		*/
		if (this->at(i).is_mnemonic(UD_Ixchg) &&
			this->at(i + 1).compare_mnemonic(false, true, true) &&
			this->at(i + 2).is_mnemonic(UD_Ixchg) &&
			((this->at(i + 2).is_operand(0, this->at(i), 0) && this->at(i + 2).is_operand(1, this->at(i), 1)) ||
			(this->at(i + 2).is_operand(0, this->at(i), 1) && this->at(i + 2).is_operand(1, this->at(i), 0))))
		{
			/* 1: ___ x1,(imm) */
			if (this->at(i + 1).is_operand(0, this->at(i), 0) &&
				this->at(i + 1).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
			{
				/* 0: ___ x2,(imm) */
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i), 1);
				this->at(i).set_operand(1, this->at(i + 1), 1);

				this->remove(i + 1, 2);
			}
			/* 1: ___ x2,(imm) */
			else if (this->at(i + 1).is_operand(0, this->at(i), 1) &&
				this->at(i + 1).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
			{
				/* 0: ___ x1,(imm) */
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i), 0);
				this->at(i).set_operand(1, this->at(i + 1), 1);

				this->remove(i + 1, 2);
			}
		}
		
		/*
			0: xchg x1,x2
			1: ___ ___,___
			2: ___ ___,___
			3: xchg x1,x2
		*/
		if (this->bounds(i, 3) &&
			this->at(i).is_mnemonic(UD_Ixchg) &&
			this->at(i + 1).compare_mnemonic(false, true, true) &&
			this->at(i + 2).compare_mnemonic(false, true, true) &&
			this->at(i + 3).is_mnemonic(UD_Ixchg) &&
			((this->at(i + 3).is_operand(0, this->at(i), 0) && this->at(i + 3).is_operand(1, this->at(i), 1)) ||
			(this->at(i + 3).is_operand(0, this->at(i), 1) && this->at(i + 3).is_operand(1, this->at(i), 0))))
		{
			/*
				1: ___ x1,(imm)
				2: ___ x1,(imm)
			*/
			if (this->at(i + 1).is_operand(0, this->at(i), 0) &&
				this->at(i + 1).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }) &&
				this->at(i + 2).is_operand(0, this->at(i + 1), 0) &&
				this->at(i + 2).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
			{
				/*
					0: ___ x2,(imm)
					1: ___ x2,(imm)
				*/
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i), 1);
				this->at(i).set_operand(1, this->at(i + 1), 1);
				
				this->at(i + 1).set_mnemonic(this->at(i + 2));
				this->at(i + 1).set_operand(0, this->at(i), 0);
				this->at(i + 1).set_operand(1, this->at(i + 2), 1);

				this->remove(i + 2, 2);
			}
			/* 1: ___ x2,imm */
			else if (this->at(i + 1).is_operand(0, this->at(i), 1) &&
				this->at(i + 1).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
			{
				/*
					0: ___ x1,(imm)
					1: ___ x1,___
				*/
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand(0, this->at(i), 0);
				this->at(i).set_operand(1, this->at(i + 1), 1);
				
				this->at(i + 1).set_mnemonic(this->at(i + 2));
				this->at(i + 1).set_operand(0, this->at(i), 0);
				this->at(i + 1).set_operand(1, this->at(i + 2), 1);

				this->remove(i + 2, 2);
			}
		}

		/*
			0: push ___
			1: mov ___,___
			2: pop ___
		*/
		if (this->bounds(i, 2) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 2).is_mnemonic(UD_Ipop))
		{
			/*
				0: push reg
				1: mov ___,reg
			*/
			if (this->at(i).is_operand_type(0, UD_OP_REG) &&
				this->at(i + 1).is_operand_type(1, UD_OP_REG))
			{
				/*
					0: push x1
					1: mov x1,x2
					2: pop x2
				*/
				if (this->at(i + 1).is_operand(0, this->at(i), 0) &&
					this->at(i + 2).is_operand(0, this->at(i + 1), 1))
				{
					/* 0: xchg x1,x2 */
					this->at(i).set_mnemonic(UD_Ixchg);
					this->at(i).set_operand(1, this->at(i + 1), 1);

					this->remove(i + 1, 2);
				}
			}
			/*
				0: push unknown ptr [mem]
				1: mov ___,reg
			*/
			else if (this->at(i).is_operand_type(0, UD_OP_MEM) &&
				this->at(i + 1).is_operand_type(1, UD_OP_REG))
			{
				/*
					0: push unknown ptr [mem]
					1: mov unknown ptr [mem],reg
					2: pop reg
				*/
				if (this->at(i + 1).is_operand_type(0, this->at(i), 0) &&
					this->at(i + 2).is_operand(0, this->at(i + 1), 1))
				{
					/*
						0: push (d)word ptr [esp+xx]
						1: mov (d)word ptr [esp+xx+02/04],reg
						2: pop reg
					*/
					if (this->at(i).is_operand_base(0, UD_R_ESP) &&
						this->at(i).is_operand_index(0, this->at(i + 1), 0) &&
						this->at(i).is_operand_scale(0, this->at(i + 1), 0) &&
						this->at(i).is_operand_data(0, this->at(i + 1).get_operand_data(0) + (this->at(i).is_operand_size(0, UD_SIZE_DWORD) ? 4 : 2))) 
					{
						/* 0: xchg (d)word ptr [esp+xx],reg */
						this->at(i).set_mnemonic(UD_Ixchg);
						this->at(i).set_operand(1, this->at(i + 1), 1);
						
						this->remove(i + 1, 2);
					}
					/*
						0: push unknown ptr [mem]
						1: mov unknown ptr [mem],reg
						2: pop reg
					*/
					else if (this->at(i).is_operand(0, this->at(i + 1), 0))
					{
						/* 0: xchg unknown ptr [mem],reg */
						this->at(i).set_mnemonic(UD_Ixchg);
						this->at(i).set_operand(1, this->at(i + 1), 1);
						
						this->remove(i + 1, 2);
					}
				}
			}
			/*
				0: push reg
				1: mov ___,unknown ptr [mem]
			*/
			else if (this->at(i).is_operand_type(0, UD_OP_REG) &&
				this->at(i + 1).is_operand_type(1, UD_OP_MEM))
			{
				/*
					0: push reg
					1: mov reg,unknown ptr [mem]
					2: pop unknown ptr [mem]
				*/
				if (this->at(i + 1).is_operand(0, this->at(i), 0) &&
					this->at(i + 2).is_operand_type(0, this->at(i + 1), 1))
				{
					/*
						0: push reg
						1: mov reg,(d)word ptr [esp+xx+04]
						2: pop (d)word ptr [esp+xx]
					*/
					if (this->at(i + 1).is_operand_base(1, UD_R_ESP) &&
						this->at(i + 1).is_operand_index(1, this->at(i + 2), 0) &&
						this->at(i + 1).is_operand_scale(1, this->at(i + 2), 0) &&
						this->at(i + 1).is_operand_data(1, this->at(i + 2).get_operand_data(0) + (this->at(i + 1).is_operand_size(1, UD_SIZE_DWORD) ? 4 : 2)))
					{
						/* 0: xchg reg,(d)word ptr [esp+xx] */
						this->at(i).set_mnemonic(UD_Ixchg);
						this->at(i).set_operand(1, this->at(i + 2), 0);
						
						this->remove(i + 1, 2);
					}
					/*
						0: push reg
						1: mov reg,unknown ptr [mem]
						2: pop unknown ptr [mem]
					*/
					else if (this->at(i + 1).is_operand(1, this->at(i + 2), 0))
					{
						/* 0: xchg reg,unknown ptr [mem] */
						this->at(i).set_mnemonic(UD_Ixchg);
						this->at(i).set_operand(1, this->at(i + 1), 1);
						
						this->remove(i + 1, 2);
					}
				}
			}
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_arithmetics()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: push reg
			1: mov reg,x1
			2: ___ x2,reg
			3: pop reg
		*/
		if (this->bounds(i, 3) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			
			this->at(i + 2).compare_mnemonic(true, false, true) &&
			this->at(i + 2).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(1, this->at(i + 1), 0) &&

			this->at(i + 3).is_mnemonic(UD_Ipop) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(0, this->at(i), 0))
		{
			/* 0: ___ x2,x1 */
			if (this->at(i + 2).is_operand_type(0, UD_OP_MEM) && this->at(i + 2).is_operand_base(0, UD_R_ESP))
				this->at(i + 2).dec_operand_data<uint32_t>(0, this->at(i).is_operand_base_size(0, UD_SIZE_DWORD) ? 4 : 2);

			this->at(i).set_mnemonic(this->at(i + 2));
			this->at(i).set_prefixes(this->at(i + 2));
			this->at(i).set_operand(0, this->at(i + 2), 0);
			this->at(i).set_operand(1, this->at(i + 1), 1);

			this->remove(i + 1, 3);
		}

		/*
			0: push reg/unknown ptr [mem]
			1: ___ esp/unknown ptr [esp+xx],(___)
			2: pop reg/unknown ptr [mem]
		*/
		if (this->bounds(i, 2) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&

			this->at(i + 1).compare_mnemonic(false, true, true) &&
			this->at(i + 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&

			this->at(i + 2).is_mnemonic(UD_Ipop) &&
			this->at(i + 2).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 2).is_operand(0, this->at(i), 0))
		{
			/*
				0: push reg
				1: ___ byte ptr [esp+01],(___)
			*/
			if (this->at(i).is_operand_type(0, UD_OP_REG) &&
				this->at(i).is_operand_base_family(0, { UD_R_EAX, UD_R_ECX, UD_R_EDX, UD_R_EBX }) &&
				this->at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_BYTE) &&
				this->at(i + 1).is_operand_data(0, 1))
			{
				/* 0: ___ reg,(___) */
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand_type(0, this->at(i + 2), 0);
				this->at(i).set_operand_size(0, UD_SIZE_BYTE);
				this->at(i).set_operand_base(0, this->at(i + 2).get_base_high_type(0));
				this->at(i).set_operand(1, this->at(i + 1), 1);

				this->remove(i + 1, 2);
			}
			/* 1: ___ esp/unknown ptr [esp],(___) */
			else if (this->at(i + 1).has_operand_data_not(0))
			{
				/* 0: ___ reg/unknown ptr [mem],(___) */
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_prefixes(this->at(i + 1));
				this->at(i).set_operand_type(0, this->at(i + 2), 0);
				
				if (this->at(i + 2).is_operand_type(0, UD_OP_REG))
				{
					this->at(i).set_operand_size(0, this->at(i + 1).get_operand_size(0));
					this->at(i).set_operand_base(0, this->at(i + 2).get_base_size_type(0, this->at(i + 1).get_operand_size(0)));
				}
				else
				{
					this->at(i).set_operand_type(0, this->at(i + 2).get_operand_type(0), this->at(i + 1).get_operand_size(0));
				}

				this->at(i).set_operand(1, this->at(i + 1), 1);

				this->remove(i + 1, 2);
			}
		}
		
		/*
			0: push reg
			1: ___ esp/unknown ptr [esp+xx],(___)
			2: ___ esp/unknown ptr [esp+xx],(___)
			3: pop reg
		*/
		if (this->bounds(1, 3) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			
			this->at(i + 1).compare_mnemonic(false, true, true) &&
			this->at(i + 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			
			this->at(i + 2).compare_mnemonic(false, true, true) &&
			this->at(i + 2).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 2).is_operand(0, this->at(i + 1), 0) &&

			this->at(i + 3).is_mnemonic(UD_Ipop) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand(0, this->at(i), 0))
		{
			/*
				0: push reg
				1: ___ byte ptr [esp+01],(___)
				2: ___ byte ptr [esp+01],(___)
			*/
			if (this->at(i).is_operand_type(0, UD_OP_REG) &&
				this->at(i).is_operand_base_family(0, { UD_R_EAX, UD_R_ECX, UD_R_EDX, UD_R_EBX }) &&
				this->at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_BYTE) &&
				this->at(i + 1).is_operand_data(0, 1))
			{
				/*
					0: ___ byte ptr reg,(___)
					1: ___ byte ptr reg,(___)
				*/
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_operand_type(0, this->at(i + 3), 0);
				this->at(i).set_operand_size(0, UD_SIZE_BYTE);
				this->at(i).set_operand_base(0, this->at(i + 3).get_base_high_type(0));
				this->at(i).set_operand(1, this->at(i + 1), 1);
				
				this->at(i + 1).set_mnemonic(this->at(i + 2));
				this->at(i + 1).set_operand_type(0, this->at(i + 3), 0);
				this->at(i + 1).set_operand_size(0, UD_SIZE_BYTE);
				this->at(i + 1).set_operand_base(0, this->at(i + 3).get_base_high_type(0));
				this->at(i + 1).set_operand(1, this->at(i + 2), 1);

				this->remove(i + 2, 2);
			}
			/* 1: ___ esp/unknown ptr [esp],(___) */
			else if (this->at(i + 1).has_operand_data_not(0))
			{
				/*
					0: ___ unknown ptr reg,(___)
					1: ___ unknown ptr reg,(___)
				*/
				this->at(i).set_mnemonic(this->at(i + 1));
				this->at(i).set_prefixes(this->at(i + 1));
				this->at(i).set_operand_type(0, this->at(i + 3), 0);

				if (this->at(i + 3).is_operand_type(0, UD_OP_REG))
				{
					this->at(i).set_operand_size(0, this->at(i + 1).get_operand_size(0));
					this->at(i).set_operand_base(0, this->at(i + 3).get_base_size_type(0, this->at(i + 1).get_operand_size(0)));
					this->at(i).set_operand_index_null(0);
					this->at(i).set_operand_scale_null(0);
					this->at(i).set_operand_data_null(0);
				}
				else
				{
					this->at(i).set_operand_type(0, this->at(i + 3).get_operand_type(0), this->at(i + 1).get_operand_size(0));
				}

				this->at(i).set_operand(1, this->at(i + 1), 1);
			
				this->at(i + 1).set_mnemonic(this->at(i + 2));
				this->at(i + 1).set_prefixes(this->at(i + 2));
				this->at(i + 1).set_operand_type(0, this->at(i + 3), 0);
				
				if (this->at(i + 3).is_operand_type(0, UD_OP_REG))
				{
					this->at(i + 1).set_operand_size(0, this->at(i + 2).get_operand_size(0));
					this->at(i + 1).set_operand_base(0, this->at(i + 3).get_base_size_type(0, this->at(i + 2).get_operand_size(0)));
					this->at(i + 1).set_operand_index_null(0);
					this->at(i + 1).set_operand_scale_null(0);
					this->at(i + 1).set_operand_data_null(0);
				}
				else
				{
					this->at(i + 1).set_operand_type(0, this->at(i + 3).get_operand_type(0), this->at(i + 2).get_operand_size(0));
				}

				this->at(i + 1).set_operand(1, this->at(i + 2), 1);

				this->remove(i + 2, 2);
			}
		}

			
		/*
			0: push reg
			1: mov reg,x
			2: ___ reg,___
			3: mov x,reg
			4: pop reg
		*/
		if (this->bounds(1, 4) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
		
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG) &&

			(this->at(i + 2).compare_mnemonic(false, true, true) || this->at(i + 2).compare_immediate()) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			
			this->at(i + 3).is_mnemonic(UD_Imov) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(0, this->at(i + 1), 1) &&
			this->at(i + 3).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(1, this->at(i + 1), 0) &&
			this->at(i + 3).is_operand_base(1, this->at(i + 2), 0) &&

			this->at(i + 4).is_mnemonic(UD_Ipop) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i), 0))
		{
			/* 0: ___ x,___ */
			this->at(i).set_mnemonic(this->at(i + 2));
			this->at(i).set_prefixes(this->at(i + 2));
			this->at(i).set_operand(0, this->at(i + 3), 0);
			this->at(i).set_operand(1, this->at(i + 2), 1);

			this->remove(i + 1, 4);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_offset()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: add|sub x1,imm
			1: add/sub x1,___
			2: sub|add x1,imm
		*/
		if (this->bounds(i, 2) &&
			((this->at(i).is_mnemonic(UD_Iadd) && this->at(i + 2).is_mnemonic(UD_Isub)) ||
			(this->at(i).is_mnemonic(UD_Isub) && this->at(i + 2).is_mnemonic(UD_Iadd))) &&
			this->at(i).is_operand_type(1, UD_OP_IMM) &&

			this->at(i + 1).is_mnemonic({ UD_Iadd, UD_Isub }) &&
			this->at(i + 1).is_operand(0, this->at(i), 0) &&
			this->at(i + 1).is_operand_type_not(1, UD_OP_IMM) && 
			
			this->at(i + 2).is_operand(0, this->at(i + 1), 0) &&
			this->at(i + 2).is_operand_type(1, UD_OP_IMM) &&
			this->at(i + 2).is_operand_data(1, this->at(i), 1))
		{
			/* 0: add/sub x1,___ */
			this->at(i).set_mnemonic(this->at(i + 1));
			this->at(i).set_operand(1, this->at(i + 1), 1);

			this->remove(i + 1, 2);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_generated_memory()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: push reg
			1: mov reg,reg/imm
		*/
		if (this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, { UD_OP_REG, UD_OP_IMM }))
		{
			/* 1: mov reg,reg */
			if (this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
				this->at(i + 1).is_operand_base(1, this->at(i + 1), 0))
			{
				continue;
			}

			/* 1: mov regx,reg/imm */
			if (this->at(i + 1).is_operand_base(0, this->at(i), 0))
			{
				ud_type base_type = UD_NONE;
				uint32_t registers = 0;
					
				/*
					0: push regx
					1: mov regx,regb
				*/
				if (this->at(i + 1).is_operand_base(0, this->at(i), 0) &&
					this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
					this->at(i + 1).is_operand_base_not(1, this->at(i + 1), 0))
				{
					base_type = this->at(i + 1).get_base_type(1);
					registers++;
				}

				bool is_valid = true;

				std::size_t j = 0;
				std::size_t index = 0;

				for (j = 0; j < (this->size() - (i + 2)); j++)
				{
					index = (i + 2 + j);

					/* 2+j: ___ ___,___ */
					if (!this->at(index).compare_mnemonic(true, true, true))
					{
						is_valid = false;
						break;
					}

					/* 2+j: (___ != mov) reg,(imm) */
					if (this->at(index).is_mnemonic_not(UD_Imov) &&
						this->at(index).is_operand_type(0, UD_OP_REG) &&
						this->at(index).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
					{
						/* 2+j: (___ != mov) (reg != regx),(imm) */
						if (this->at(index).is_operand_base_not(0, this->at(i + 1), 0))
						{
							is_valid = false;
							break;
						}
					}
					/* 2+j: (___ != mov) reg,reg  */
					else if (this->at(index).is_mnemonic_not(UD_Imov) &&
						this->at(index).is_operand_type(0, UD_OP_REG) &&
						this->at(index).is_operand_type(1, UD_OP_REG) &&
						this->at(index).is_operand_base_not(1, this->at(index), 0))
					{
						/* 2+j: (___ != mov) (reg != regx),reg */
						if (this->at(index).is_operand_base_not(0, this->at(i + 1), 0))
						{
							is_valid = false;
							break;
						}
						
						base_type = this->at(index).get_base_type(1);
						registers++;
					}
					else
					{
						/* 2+j: ___ reg,unknown ptr [mem] */
						if (this->at(index).is_operand_type(0, UD_OP_REG) &&
							this->at(index).is_operand_type(1, UD_OP_MEM))
						{
							/*
								2+j:	___ reg,unknown ptr [regx]
								2+j+1:	pop regx
							*/
							if (this->bounds(index, 1) &&
								(this->at(index).is_operand_base(0, this->at(i + 1), 0) ||
								this->at(index).is_operand_base_not(1, this->at(i + 1), 0) ||
								this->at(index).has_operand_index(1) ||
								this->at(index).has_operand_scale(1) ||
								this->at(index).has_operand_data(1) ||
								
								this->at(index + 1).is_mnemonic_not(UD_Ipop) ||
								this->at(index + 1).is_operand_type_not(0, UD_OP_REG) ||
								this->at(index + 1).is_operand_base_not(0, this->at(index), 1) ||
								this->at(index + 1).is_operand_base_not(0, this->at(i), 0)))
							{
								is_valid = false;
							}
						}
						/* 2+j: ___ unknown ptr [mem],reg */
						else if (this->at(index).is_operand_type(0, UD_OP_MEM) &&
							this->at(index).is_operand_type(1, UD_OP_REG))
						{
							/*
								2+j:	___ unknown ptr [regx],reg
								2+j+1:	pop regx
							*/
							if (this->bounds(index, 1) &&
								(this->at(index).is_operand_base(1, this->at(i + 1), 0) ||
								this->at(index).is_operand_base_not(0, this->at(i + 1), 0) ||
								this->at(index).has_operand_index(0) ||
								this->at(index).has_operand_scale(0) ||
								this->at(index).has_operand_data(0) ||
								
								this->at(index + 1).is_mnemonic_not(UD_Ipop) ||
								this->at(index + 1).is_operand_type_not(0, UD_OP_REG) ||
								this->at(index + 1).is_operand_base_not(0, this->at(index), 0) ||
								this->at(index + 1).is_operand_base_not(0, this->at(i), 0)))
							{
								is_valid = false;
							}
						}
						/* 2+j: ___ unknown ptr [mem],imm */
						else if (this->at(index).is_operand_type(0, UD_OP_MEM) &&
							this->at(index).is_operand_type(1, { UD_OP_IMM, UD_OP_CONST }))
						{
							/*
								2+j:	___ unknown ptr [regx],imm
								2+j+1:	pop regx
							*/
							if (this->bounds(index, 1) &&
								(this->at(index).is_operand_base_not(0, this->at(i + 1), 0) ||
								this->at(index).has_operand_index(0) ||
								this->at(index).has_operand_scale(0) ||
								this->at(index).has_operand_data(0) ||
								
								this->at(index + 1).is_mnemonic_not(UD_Ipop) ||
								this->at(index + 1).is_operand_type_not(0, UD_OP_REG) ||
								this->at(index + 1).is_operand_base_not(0, this->at(index), 0) ||
								this->at(index + 1).is_operand_base_not(0, this->at(i), 0)))
							{
								is_valid = false;
							}
						}
						else
						{
							is_valid = false;
						}

						break;
					}
				}

				if (is_valid && registers == 1)
				{
					this->at(i).set_mnemonic(this->at(index));
					this->at(i).set_prefixes(this->at(index));

					uint32_t imm_product = 0;
					ud_size imm_size = UD_SIZE_NONE;

					for (std::size_t k = 0; k < (j + 1); k++)
					{
						if (this->at(i + 1 + k).is_operand_type_not(1, UD_OP_REG))
						{
							if (k == 0)
								imm_product = this->at(i + 1).get_operand_data(1);
							else
								instruction::emulate(this->at(i + 1 + k).get_mnemonic(), this->at(i + 1).get_base_size(0), this->at(i + 1 + k).get_operand_data(1), &imm_product);
						}
					}

					if (this->at(index).is_operand_type(1, UD_OP_MEM))
					{
						/* 0: ___ reg,unknown ptr [regb+d] ; b = regb, d = imm (product) */
						this->at(i).set_operand(0, this->at(index), 0);
						this->at(i).set_operand(1, this->at(index), 1);
						this->at(i).set_operand_base(1, base_type);
						this->at(i).set_operand_index_null(1);
						this->at(i).set_operand_scale_null(1);
						this->at(i).set_operand_offset(1, UD_SIZE_DWORD);
						this->at(i).set_operand_data(1, imm_product);
					}
					else
					{
						/* 0: ___ unknown ptr [regb+d],___ ; b = regb, d = imm (product) */
						this->at(i).set_operand(0, this->at(index), 0);
						this->at(i).set_operand_base(0, base_type);
						this->at(i).set_operand_index_null(0);
						this->at(i).set_operand_scale_null(0);
						this->at(i).set_operand_offset(0, UD_SIZE_DWORD);
						this->at(i).set_operand_data(0, imm_product);
						this->at(i).set_operand(1, this->at(index), 1);
					}

					this->remove(i + 1, 2 + j + 1);
				}
			}
		}

		
		/*
			0: push reg (x)
			1: mov x,reg (i)
			2: shl x,imm (s)
			3: add x,imm (d)
			4: add x,reg (b)
			5: ___ ___,unknown ptr [x]
			5: ___ unknown ptr [x],___
			6: pop x
		*/
		if (this->bounds(1, 6) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_base(0, this->at(i), 0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 1).is_operand_base_not(1, this->at(i + 1), 0) &&
			
			this->at(i + 2).is_mnemonic(UD_Ishl) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(0, this->at(i + 1), 0) &&
			this->at(i + 2).is_operand_type(1, { UD_OP_IMM, UD_OP_CONST }) &&
			
			this->at(i + 3).is_mnemonic(UD_Iadd) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(0, this->at(i + 2), 0) &&
			this->at(i + 3).is_operand_type(1, UD_OP_IMM) &&
			
			this->at(i + 4).is_mnemonic(UD_Iadd) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i + 3), 0) &&
			this->at(i + 4).is_operand_type(1, UD_OP_REG) &&

			this->at(i + 5).compare_mnemonic(true, false, true) &&
			((this->at(i + 5).is_operand_type(0, UD_OP_MEM) &&
			this->at(i + 5).is_operand_base(0, this->at(i + 2), 0) &&
			this->at(i + 5).has_operand_index_not(0) &&
			this->at(i + 5).has_operand_scale_not(0) &&
			this->at(i + 5).has_operand_data_not(0)) ||
			(this->at(i + 5).is_operand_type(1, UD_OP_MEM) &&
			this->at(i + 5).is_operand_base(1, this->at(i + 2), 0) &&
			this->at(i + 5).has_operand_index_not(1) &&
			this->at(i + 5).has_operand_scale_not(1) &&
			this->at(i + 5).has_operand_data_not(1))) &&
			
			this->at(i + 6).is_mnemonic(UD_Ipop) &&
			this->at(i + 6).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 6).is_operand_base(0, this->at(i), 0))
		{
			this->at(i).set_mnemonic(this->at(i + 5));
			this->at(i).set_prefixes(this->at(i + 5));

			/* 5: ___ ___,unknown ptr [mem] */
			if (this->at(i + 5).is_operand_type(1, UD_OP_MEM))
			{
				/* 0: ___ ___,unknown ptr [b+i*s+d] */
				if (this->at(i + 5).is_operand_base(1, UD_R_ESP))
					this->at(i + 5).dec_operand_data<uint32_t>(1, this->at(i).get_base_size(0) == UD_SIZE_DWORD ? 4 : 2);

				this->at(i).set_operand(0, this->at(i + 5), 0);

				this->at(i).set_operand_type(1, this->at(i + 5), 1);
				this->at(i).set_operand_base(1, this->at(i + 4), 1);
				this->at(i).set_operand_index(1, this->at(i + 1), 1);
				this->at(i).set_operand_scale_by_exponent(1, this->at(i + 2).get_operand_data<uint8_t>(1));
				this->at(i).set_operand_data(1, this->at(i + 3), 1);
			}
			/* 5: ___ unknown ptr [mem],___ */
			else
			{
				/* 0: ___ unknown ptr [b+i*s+d],___ */
				if (this->at(i + 5).is_operand_base(0, UD_R_ESP))
					this->at(i + 5).dec_operand_data<uint32_t>(0, this->at(i).get_base_size(0) == UD_SIZE_DWORD ? 4 : 2);

				this->at(i).set_operand(1, this->at(i + 5), 1);

				this->at(i).set_operand_type(0, this->at(i + 5), 0);
				this->at(i).set_operand_base(0, this->at(i + 4), 1);
				this->at(i).set_operand_index_by_base(0, this->at(i + 1), 1);
				this->at(i).set_operand_scale_by_exponent(0, this->at(i + 2).get_operand_data<uint8_t>(1));
				this->at(i).set_operand_data(0, this->at(i + 3), 1);
			}

			this->remove(i + 1, 6);
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_generated_register()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: push reg
			1: mov reg,imm
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM))
		{
			bool is_valid = true;

			std::size_t j = 0;
			std::size_t index = 0;

			for (j = 0; j < (this->size() - (i + 2)); j++)
			{
				index = (i + 2 + j);

				/* 2+j: ___ ___,___ */
				if (this->at(index).compare_mnemonic_not(true, true, true))
				{
					is_valid = false;
					break;
				}
				
				/* 2+j: (___ != mov) reg,(imm) */
				if (this->at(index).is_mnemonic_not(UD_Imov) &&
					this->at(index).is_operand_type(0, UD_OP_REG) &&
					this->at(index).is_operand_type(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
				{
					if (this->at(index).is_operand_base_not(0, this->at(i + 1), 0))
					{
						is_valid = false;
						break;
					}
				}
				else
				{
					/* 2+j: ___ reg,reg */
					if (this->at(index).is_operand_type(0, UD_OP_REG) &&
						this->at(index).is_operand_type(1, UD_OP_REG))
					{
						if (this->bounds(index, 1) &&
							this->at(index).is_operand_base(0, this->at(i + 1), 0) ||
							this->at(index + 1).is_mnemonic_not(UD_Ipop) ||
							this->at(index + 1).is_operand_type_not(0, UD_OP_REG) ||
							this->at(index + 1).is_operand_base_not(0, this->at(i), 0) ||
							this->at(index + 1).compare_base_not(0, this->at(index), 1))
						{
							is_valid = false;
						}
					}
					/* 2+j: ___ unknown ptr [mem],reg */
					else if (this->at(index).is_operand_type(0, UD_OP_MEM) &&
						this->at(index).is_operand_type(1, UD_OP_REG))
					{
						if (this->bounds(index, 1) &&
							this->at(index + 1).is_mnemonic_not(UD_Ipop) ||
							this->at(index + 1).is_operand_type_not(0, UD_OP_REG) ||
							this->at(index + 1).is_operand_base_not(0, this->at(i), 0) ||
							this->at(index + 1).compare_base_not(0, this->at(index), 1))
						{
							is_valid = false;
						}
					}
					else
					{
						is_valid = false;
					}

					break;
				}
			}

			if (is_valid)
			{
				this->at(i).set_mnemonic(this->at(index));
				this->at(i).set_prefixes(this->at(index));
				
				this->at(i).set_operand(0, this->at(index), 0);
				this->at(i).set_operand(1, this->at(i + 1), 1);

				uint32_t imm_product = this->at(i + 1).get_operand_data<uint32_t>(1);

				for (std::size_t k = 0; k < j; k++)
					instruction::emulate(this->at(i + 2 + k).get_mnemonic(), this->at(i + 1).get_base_size(0), this->at(i + 2 + k).get_operand_data(1), &imm_product);

				this->at(i).set_operand_data(1, imm_product);

				if (this->at(i).is_operand_type(0, UD_OP_MEM) && this->at(i).is_operand_base(0, UD_R_ESP))
					this->at(i).dec_operand_data<uint32_t>(0, this->at(index + 1).is_operand_base_size(0, UD_SIZE_DWORD) ? 4 : 2);

				this->remove(i + 1, 2 + j + 1);
			}
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_neg()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/*
			0: push 0
			1: sub unknown ptr [esp],reg
			2: pop reg
		*/
		if (this->bounds(i, 2) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_IMM) &&
			this->at(i).is_operand_data(0, 0) &&

			this->at(i + 1).is_mnemonic(UD_Isub) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			this->at(i + 1).has_operand_data_not(0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 1).is_operand_base_not(1, UD_R_ESP) &&

			this->at(i + 2).is_mnemonic(UD_Ipop) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(0, this->at(i + 1), 1))
		{
			/* 0: neg reg */
			this->at(i).set_mnemonic(UD_Ineg);
			this->at(i).set_operand(0, this->at(i + 1), 1);

			this->remove(i + 1, 2);
		}

		/* 0: not ___ */
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Inot))
		{
			/* 1: inc ___ */
			if (this->at(i + 1).is_mnemonic(UD_Iinc))
			{
				/*
					0: not reg/unknown ptr [mem]
					1: inc reg/unknown ptr [mem]
				*/
				if (this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i).is_operand(0, this->at(i + 1), 0))
				{
					/* 0: neg reg/unknown ptr [mem] */
					this->at(i).set_mnemonic(UD_Ineg);

					this->remove(i + 1);
				}
			}
			/* 1: add ___,___ */
			else if (this->at(i + 1).is_mnemonic(UD_Iadd))
			{
				/*
					0: not reg/unknown ptr [mem]
					1: add reg/unknown ptr [mem],1
				*/
				if (this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i).is_operand(0, this->at(i + 1), 0) &&
					this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&
					this->at(i + 1).is_operand_data(1, 1))
				{
					/* 0: neg reg/unknown ptr [mem] */
					this->at(i).set_mnemonic(UD_Ineg);

					this->remove(i + 1);
				}
			}
			/* 1: sub ___,___ */
			else if (this->at(i + 1).is_mnemonic(UD_Isub))
			{
				/*
					0: not reg/unknown ptr [mem]
					1: sub reg/unknown ptr [mem],-1
				*/
				if (this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i).is_operand(0, this->at(i + 1), 0) && 
					this->at(i + 1).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE) &&
					this->at(i + 1).is_operand_data(1, { 255, -1 }))
				{
					/* 0: neg reg/unknown ptr [mem] */
					this->at(i).set_mnemonic(UD_Ineg);

					this->remove(i + 1);
				}
			}
		}

		/* 1: not ___ */
		if (this->bounds(i, 1) &&
			this->at(i + 1).is_mnemonic(UD_Inot))
		{
			/* 0: dec ___ */
			if (this->at(i).is_mnemonic(UD_Idec))
			{
				/*
					0: dec reg/unknown ptr [mem]
					1: not reg/unknown ptr [mem]
				*/
				if (this->at(i + 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i + 1).is_operand(0, this->at(i), 0))
				{
					/* 0: neg reg/unknown ptr [mem] */
					this->at(i).set_mnemonic(UD_Ineg);

					this->remove(i + 1);
				}
			}
			/*
				0: add ___
				1: not ___
			*/
			else if (this->at(i).is_mnemonic(UD_Iadd))
			{
				/*
					0: add reg/unknown ptr [mem],255/-1
					1: not reg/unknown ptr [mem]
				*/
				if (this->at(i).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE) &&
					this->at(i).is_operand_data(1, { 255, -1 }) &&
					this->at(i + 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i + 1).is_operand(0, this->at(i), 0))
				{
					/* 0: neg reg/unknown ptr [mem] */
					this->at(i).set_mnemonic(UD_Ineg);
					this->at(i).set_operand_null(1);

					this->remove(i + 1);
				}
			}
			/* 0: sub ___,___ */
			else if (this->at(i).is_mnemonic(UD_Isub))
			{
				/*
					0: sub reg/unknown ptr [mem],1
					1: not reg/unknown ptr [mem]
				*/
				if (this->at(i).is_operand_type(1, UD_OP_IMM) &&
					this->at(i).is_operand_data(1, 1) &&
					this->at(i + 1).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
					this->at(i + 1).is_operand(0, this->at(i), 0))
				{
					/* 0: neg [mem]/reg */
					this->at(i).set_mnemonic(UD_Ineg);
					this->at(i).set_operand_null(1);

					this->remove(i + 1);
				}
			}
		}

		/*
			0: push 0
			1: sub byte ptr [esp],(reg != esp)
			2: mov reg,byte ptr [esp]
			3: add esp,02/04
		*/
		if (this->bounds(i, 3) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_IMM) &&
			this->at(i).is_operand_data(0, 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Isub) &&
			this->at(i + 1).is_operand_type(0, UD_OP_MEM, UD_SIZE_BYTE) &&
			this->at(i + 1).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 1).has_operand_index_not(0) &&
			this->at(i + 1).has_operand_scale_not(0) &&
			this->at(i + 1).has_operand_data_not(0) &&
			this->at(i + 1).is_operand_type(1, UD_OP_REG) &&
			this->at(i + 1).is_operand_base_not(1, UD_R_ESP) &&
			
			this->at(i + 2).is_mnemonic(UD_Imov) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(0, this->at(i + 1), 1) &&
			this->at(i + 2).is_operand_type(1, UD_OP_MEM, UD_SIZE_BYTE) &&
			this->at(i + 2).is_operand_base(1, UD_R_ESP) &&
			this->at(i + 2).has_operand_index_not(1) &&
			this->at(i + 2).has_operand_scale_not(1) &&
			this->at(i + 2).has_operand_data_not(1) &&
			
			this->at(i + 3).is_mnemonic(UD_Iadd) &&
			this->at(i + 3).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 3).is_operand_base(0, UD_R_ESP) &&
			this->at(i + 3).is_operand_type(1, UD_OP_IMM) &&
			((this->at(i + 3).is_operand_data(1, 2) && this->at(i).is_operand_size(0, UD_SIZE_WORD)) ||
			(this->at(i + 3).is_operand_data(1, 4) && this->at(i).is_operand_size(0, UD_SIZE_DWORD))))
		{
			/* 0: neg reg */
			this->at(i).set_mnemonic(UD_Ineg);
			this->at(i).set_operand(0, this->at(i + 1), 1);

			this->remove(i + 1, 3);
		}

		/*
			0: push reg
			1: mov reg,0
			2: sub reg,x1
			3: mov/xchg reg/unknown ptr [mem],reg/unknown ptr [mem]
			4: pop reg
		*/
		if (this->bounds(i, 4) &&
			this->at(i).is_mnemonic(UD_Ipush) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).compare_base(0, this->at(i + 1), 0) &&
			
			this->at(i + 1).is_mnemonic(UD_Imov) &&
			this->at(i + 1).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 1).is_operand_type(1, UD_OP_IMM) &&
			this->at(i + 1).is_operand_data(1, 0) &&
			
			this->at(i + 2).is_mnemonic(UD_Isub) &&
			this->at(i + 2).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 2).is_operand_base(0, this->at(i + 1), 0) &&
			this->at(i + 2).is_operand_type(1, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 2).is_operand_base_not(1, this->at(i + 2), 0) &&

			this->at(i + 3).is_mnemonic({ UD_Imov, UD_Ixchg }) &&
			this->at(i + 3).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i + 3).is_operand_type(1, { UD_OP_REG, UD_OP_MEM }) &&

			this->at(i + 4).is_mnemonic(UD_Ipop) &&
			this->at(i + 4).is_operand_type(0, UD_OP_REG) &&
			this->at(i + 4).is_operand_base(0, this->at(i), 0))
		{
			/* 3: mov x1,reg */
			if (this->at(i + 3).is_mnemonic(UD_Imov) &&
				this->at(i + 3).is_operand_sib(0, this->at(i + 2), 1) &&
				this->at(i + 3).is_operand_data(0, this->at(i + 2), 1) &&
				this->at(i + 3).is_operand_base(1, this->at(i + 2), 0))
			{
				/* 0: neg x1 */
				this->at(i).set_mnemonic(UD_Ineg);
				this->at(i).set_prefixes(this->at(i + 2));
				this->at(i).set_operand(0, this->at(i + 2), 1);

				this->remove(i + 1, 4);
			}
			/* 3: xchg x1|reg,reg|x1 */
			else if (this->at(i + 3).is_mnemonic(UD_Ixchg) &&
				((this->at(i + 3).is_operand(0, this->at(i + 2), 1) && this->at(i + 3).is_operand_base(1, this->at(i + 2), 0)) ||
				(this->at(i + 3).is_operand(1, this->at(i + 2), 1) && this->at(i + 3).is_operand_base(0, this->at(i + 2), 0))))
			{
				/* 0: neg x1 */
				this->at(i).set_mnemonic(UD_Ineg);
				this->at(i).set_prefixes(this->at(i + 2));
				this->at(i).set_operand(0, this->at(i + 2), 1);

				this->remove(i + 1, 4);
			}
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_mov_v2()
{
	for (std::size_t i = (this->size() - 1); static_cast<int32_t>(i) >= 0; i--)
	{
		/*
			0: mov reg/unknown ptr [mem],imm
			1: (___ != mov) reg/unknown ptr [mem],___
		*/
		if (this->bounds(i, 1) &&
			this->at(i).is_mnemonic(UD_Imov) &&
			this->at(i).is_operand_type(0, { UD_OP_REG, UD_OP_MEM }) &&
			this->at(i).is_operand_type(1, UD_OP_IMM) &&
			
			this->at(i + 1).is_mnemonic_not(UD_Imov) &&
			this->at(i + 1).is_operand_sib(0, this->at(i), 0) &&
			this->at(i + 1).is_operand_data(0, this->at(i), 0))
		{
			std::size_t j = 0;
			std::size_t index = 0;

			for (j = 0; j < (this->size() - (i + 1)); j++)
			{
				index = (i + 1 + j);

				/* ___ reg/unknown ptr [mem],(imm) */
				if (this->at(index).compare_mnemonic_not(false, true, true) ||
					this->at(index).is_operand_not(0, this->at(i), 0) ||
					this->at(index).is_operand_type_not(1, { UD_NONE, UD_OP_IMM, UD_OP_CONST }))
				{
					break;
				}
			}

			if (j != 0)
			{
				uint32_t imm_product = this->at(i).get_operand_data(1);

				for (std::size_t k = 0; k < j; k++)
				{
					if (this->at(i).is_operand_type(0, UD_OP_REG))
						instruction::emulate(this->at(i + 1 + k).get_mnemonic(), this->at(i).get_base_size(0), this->at(i + 1 + k).get_operand_data(1), &imm_product);
					else
						instruction::emulate(this->at(i + 1 + k).get_mnemonic(), this->at(i).get_operand_size(0), this->at(i + 1 + k).get_operand_data(1), &imm_product);
				}

				this->at(i).set_operand_data(1, imm_product);

				this->remove(i + 1, j);
			}
		}
	}
}

void instruction_container_deobfuscator::deobfuscate_fillers()
{
	for (std::size_t i = 0; i < this->size(); i++)
	{
		/* 0: mov reg,reg */
		if (this->at(i).is_mnemonic(UD_Imov) &&
			this->at(i).is_operand_type(0, UD_OP_REG) &&
			this->at(i).is_operand_type(1, UD_OP_REG) &&
			this->at(i).is_operand_base(1, this->at(i), 0))
		{
			this->remove(i--);
		}
		
		//try
		//{
		//	/* 
		//		0: pushad
		//		1: popad
		//	*/
		//	if (instructions.at(i).mnemonic == MNEMONIC_PUSHA &&
		//		instructions.at(i + 1).mnemonic == MNEMONIC_POPA)
		//	{
		//		this->remove_instructions(instructions, i, 2);
		//	}
		//}
		//catch (std::out_of_range const& e)
		//{
		//	UNREFERENCED_PARAMETER(e);
		//	/* Ignore out-of-range exceptions. They occur when (index >= size). */
		//}
		//
		//try
		//{
		//	/* 
		//		0: pushfd
		//		1: popfd
		//	*/
		//	if (instructions.at(i).mnemonic == MNEMONIC_PUSHF &&
		//		instructions.at(i + 1).mnemonic == MNEMONIC_POPF)
		//	{
		//		this->remove_instructions(instructions, i, 2);
		//	}
		//}
		//catch (std::out_of_range const& e)
		//{
		//	UNREFERENCED_PARAMETER(e);
		//	/* Ignore out-of-range exceptions. They occur when (index >= size). */
		//}
		//
		//try
		//{
		//	/*
		//		0: push x1
		//		1: pop x1
		//	*/
		//	if (instructions.at(i).mnemonic == MNEMONIC_PUSH &&
		//		instructions.at(i + 1).mnemonic == MNEMONIC_POP &&
		//		instructions.at(i).operands[0].type == instructions.at(i + 1).operands[0].type &&
		//		instructions.at(i).operands[0].size == instructions.at(i + 1).operands[0].size &&
		//		instructions.at(i).operands[0].base.type == instructions.at(i + 1).operands[0].base.type &&
		//		instructions.at(i).operands[0].base.size == instructions.at(i + 1).operands[0].base.size &&
		//		instructions.at(i).operands[0].index.type == instructions.at(i + 1).operands[0].index.type &&
		//		instructions.at(i).operands[0].index.size == instructions.at(i + 1).operands[0].index.size &&
		//		instructions.at(i).operands[0].scale == instructions.at(i + 1).operands[0].scale &&
		//		instructions.at(i).operands[0].data.dword == instructions.at(i + 1).operands[0].data.dword)
		//	{
		//		this->remove_instructions(instructions, i, 2);
		//	}
		//}
		//catch (std::out_of_range const& e)
		//{
		//	UNREFERENCED_PARAMETER(e);
		//	/* Ignore out-of-range exceptions. They occur when (index >= size). */
		//}
	}
}
//
//void oreans_deobfuscator::deobfuscate_new_types(std::vector<x86_instruction>& instructions)
//{
//	for (std::size_t i = 0; i < instructions.size(); i++)
//	{
//		try
//		{
//			/*
//				0: push reg
//				1: mov [esp],imm32
//			*/
//			if (instructions.at(i).mnemonic == MNEMONIC_PUSH &&
//				instructions.at(i).operands[0].type == OPERAND_TYPE_REGISTER &&
//				instructions.at(i + 1).mnemonic == MNEMONIC_MOV &&
//				instructions.at(i + 1).operands[0].is_type(OPERAND_TYPE_MEMORY, OPERAND_SIZE_DWORD) &&
//				instructions.at(i + 1).operands[0].has_params(true, false, false, false) &&
//				instructions.at(i + 1).operands[0].base.is_type(REGISTER_ESP, OPERAND_SIZE_DWORD) &&
//				instructions.at(i + 1).operands[1].is_type(OPERAND_TYPE_IMMEDIATE))
//			{
//				/* 0: push imm32 */
//				instructions.at(i).mnemonic = MNEMONIC_PUSH;
//				instructions.at(i).operands[0].set_type(instructions.at(i + 1).operands[1]);
//				instructions.at(i).operands[0].data.dword = instructions.at(i + 1).operands[1].data.dword;
//
//				this->remove_instructions(instructions, i + 1);
//			}
//		}
//		catch (std::out_of_range const& e)
//		{
//			UNREFERENCED_PARAMETER(e);
//			/* Ignore out-of-range exceptions. They occur when (index >= size). */
//		}
//	}
//}