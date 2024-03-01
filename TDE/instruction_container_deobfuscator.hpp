#ifndef INSTRUCTION_CONTAINER_DEOBFUSCATOR_HPP_
#define INSTRUCTION_CONTAINER_DEOBFUSCATOR_HPP_

#include "instruction_container_base.hpp"

class instruction_container_deobfuscator : public instruction_container_base
{
public:
	void deobfuscate();
	void deobfuscate_wild();

private:
	/*
		Deobfuscates the following push-obfuscation patterns:

		0: sub esp,02/04				->		0: push reg
		1: mov (d)word ptr [esp],reg

		0: push reg/imm					->		0: push reg
		1: mov (d)word ptr [esp],reg

		- Each pattern contains a special stack pattern
		1: mov (d)word ptr [esp],(e)sp	->		0: push (e)sp
		2: add unknown ptr [esp],02/04
	*/
	void deobfuscate_push();

	/*
		Deobfuscates the following pop-obfuscation patterns:

		0: mov reg,(d)word ptr [esp]	->		0: pop reg
		1: add esp,02/04

		0: mov (e)sp,(d)word ptr [esp]	->		0: pop (e)sp
	*/
	void deobfuscate_pop();	
	
	/*
		Deobfuscates the following stack-obfuscation patterns:
		
		0: push (reg != esp)			->		0: add/sub esp,imm
		1: mov reg,esp
		2: add reg,04
		3: add/sub reg,imm
		4: xchg dword ptr [esp],reg
		4: xchg reg,dword ptr [esp]
		5: pop esp
	*/
	void deobfuscate_stack();
	
	/*	
		Deobfuscates the following xchg-obfuscation patterns:
		
		0: xor x1,x2					->		0: xchg x1,x2
		1: xor x2,x1
		2: xor x1,x2
		
		0: push (reg != esp)			->		0: xchg reg,dword ptr [esp]
		1: mov reg,dword ptr [esp+4]
		2: pop dword ptr [esp]
		
		0: push reg1					->		0: xchg x2,x3
		1: mov reg1,x2
		2: mov x2,x3
		3: mov x3,reg1
		4: pop reg1
	*/
	void deobfuscate_xchg_v1();

	/*
		Deobfuscates the following mov-obfuscation patterns:
		
		0: push x1						->		0: mov x2,x1
		1: pop x2

		0: push x1						->		0: mov x2,x1
		1: sub|add|xor unknown ptr [esp],imm
		2: pop x2
		3: add|sub|xor x2,imm

		0: push reg						->		0: mov x,imm
		1: mov reg,imm
		2: mov x,imm
		3: ___ x,reg
		4: pop reg
		
		0: push reg						->		0: mov x,imm
		1: mov reg,imm
		2: mov x,imm
		3: ___ x,reg
		4: ___ x,imm
		5: pop reg
	*/
	void deobfuscate_mov_v1();
	
	/*
		Deobfuscates the following xchg-obfuscation patterns:

		0: xchg x1,x2					->		0: ___ x2/x1,(imm)
		1: ___ x1/x2,(imm)
		2: xchg x1,x2

		0: xchg x1,x2					->		0: ___ x2/x1,(imm)
		1: ___ x1/x2,(imm)						1: ___ x2/x1,(imm)
		2: ___ x1/x2,(imm)
		3: xchg x1,x2

		0: push x1						->		0: xchg x1,x2
		1: mov x1,x2
		2: pop x2

		0: push (d)word ptr [esp+xx]	->		0: xchg (d)word ptr [esp+xx],reg
		1: mov (d)word ptr [esp+xx+04],reg
		2: pop reg

		0: push reg						->		0: xchg reg,(d)word ptr [esp+xx]
		1: mov reg,(d)word ptr [esp+xx+04]
		2: pop (d)word ptr [esp+xx]
	*/
	void deobfuscate_xchg_v2();
	
	/*
		Deobfuscates the following ??-obfuscation patterns:
					
		0: push reg						->		0: ___ x2,x1
		1: mov reg,x1
		2: ___ x2,reg
		3: pop reg

		0: push reg						->		0: ___ h(reg),(___)
		1: ___ byte ptr [esp+01],(___)
		2: pop reg

		0: push reg/unknown ptr [mem]	->		0: ___ reg/unknown ptr [mem],(___)
		1: ___ esp/unknown ptr [esp],(___)
		2: pop reg/unknown ptr [mem]

		0: push reg						->		0: ___ h(reg),(___)
		1: ___ byte ptr [esp+01],(___)			1: ___ h(reg),(___)
		2: ___ byte ptr [esp+01],(___)
		3: pop reg

		0: push reg						->		0: ___ unknown ptr reg,(___)
		1: ___ esp/unknown ptr [esp],(___)		1: ___ unknown ptr reg,(___)
		2: ___ esp/unknown ptr [esp],(___)
		3: pop reg

		0: push reg						->		0: ___ x,___
		1: mov reg,x
		2: ___ reg,___
		3: mov x,reg
		4: pop reg
	*/
	void deobfuscate_arithmetics();

	/*
		Deobfuscates the following offset-obfuscation patterns:

		0: add|sub x1,imm				->		0: add/sub x1,___
		1: add/sub x1,___
		2: sub|add x1,imm
	*/
	void deobfuscate_offset();

	/*
		Deobfuscates the following generator-obfuscation patterns:
		
		0: push regx					->		0: ___ reg,unknown ptr [regb+d]			; d = imm (product)
		1: mov regx,regb				->		0: ___ unknown ptr [regb+d],reg/imm		; d = imm (product)
		j: ... imm actions ...
		j: ___ reg,unknown ptr [regx]
		j: ___ unknown ptr [regx],reg/imm
		j: ... imm actions ...
		e: pop regx
		
		0: push x (reg)					->		0: ___ ___,unknown ptr [b+i*s+d] 
		1: mov x,reg (i)						0: ___ unknown ptr [b+i*s+d],___
		2: shl x,imm (s)
		3: add x,imm (d)
		4: add x,reg (b)
		5: ___ ___,unknown ptr [x]
		5: ___ unknown ptr [x],___
		6: pop x
	*/
	void deobfuscate_generated_memory();

	/*
		Deobfuscates the following generator-obfuscation patterns:

		0: push reg						->		0: ___ reg,imm (product)
		1: mov reg,imm
		j: ... imm actions ...
		j: ___ reg,___
		j: ... imm actions ...
		e: pop reg		
	*/
	void deobfuscate_generated_register();

	/*
		Deobfuscates the following neg-obfuscation patterns:

		0: push 0						->		0: neg reg	
		1: sub unknown ptr [esp],reg
		2: pop reg

		0: not x1						->		0: neg x1
		1: inc x1

		0: not x1						->		0: neg x1
		1: add x1,1

		0: not x1						->		0: neg x1
		1: sub x1,-1
							
		0: dec x1						->		0: neg x1
		1: not x1

		0: add x1,-1					->		0: neg x1
		1: not x1

		0: sub x1,1						->		0: neg x1
		1: not x1

		0: push 0						->		0: neg reg
		1: sub byte ptr [esp],(reg != esp)
		2: mov reg,byte ptr [esp]
		3: add esp,02/04

		0: push reg						->		0: neg x1
		1: mov reg,0
		2: sub reg,x1
		3: mov x1,reg
		3: xchg x1|reg,reg|x1
		4: pop reg
	*/
	void deobfuscate_neg();

	/*
		Deobfuscates the following mov-obfuscation patterns:
			
		0: mov x,imm					->		0: mov x,imm (product)
		j: ___ x,(imm)
	*/
	void deobfuscate_mov_v2();
	
	/*
		Deobfuscates the following filler-obfuscation patterns:
			
		0: mov reg1,reg1				->		0: <removed>
	*/
	void deobfuscate_fillers();
};

#endif