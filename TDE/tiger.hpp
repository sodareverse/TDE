#ifndef TIGER_HPP_
#define TIGER_HPP_

#include "wild.hpp"

#include "tiger_context.hpp"
#include "tiger_handler.hpp"

class tiger : public wild<tiger_handler>
{
public:
	tiger();

public:
	bool is_signature(instruction_container& vm_entrance);

private:
	bool parse_initial_handler(instruction_container& instructions);
	
private:
	bool update_argument_data();

private:
	tiger_context context;
};

/*
	Machine: TIGER32 (Black/Red/White)                             

	[Main Machine Info]
	Name = (Black/Red/White)
	MachineId =  0x3E34470A/0x3E344705/0x3E344701
	MachineSignature = 0xDD82E451/0x876FB1C7/0xDA097AE9
	ProductSupport = WinLicense, Virtualizer, Themida
	FileVersionEncoded = 0x12872829
	HardwareEncryption = Not available

	[Main Machine Architecture]
	Name = TIGER32
	Bits = 32
	MaxCPUs = 8
	Emulates = IA32

	[Main Machine Stats]
	MemoryUsage = 1650/1150/550 KB
	Speed = 92/95/96
	Complexity = 25/21/15
	ScoreMultiplier = 1/20/1

	[Main Machine Processor]
	RelocateRegs = Yes
	RelocateStages = Yes
	OpcodePermutation = Yes
	RelocateHandlers = Yes
	JoinUndefinedOpcodes = No
	AllowAvidFields = Yes
	ExpandedInstructionSet = Yes
	MergeStages = Yes
	EnableRevirtualization = Yes
	EnableJoinHandlers = Yes
	EnableStageGarbage = Yes
	SmartInstructionsRelocation = Yes
	EnableHandlerTimes = Yes
	EnableBreakPoints = No
	EnableDebugMode = No
	EnableInterruptTrace = No
	EnableFakeJumps = No
	EnableFakeConditionalJumps = No
	PermutateHandlers = No
	MutateHandlers = No

	[Specific Opcodes Customization]
	Group1Mnemonics = ADD, MOV, SUB, AND, XOR, OR, POP, PUSH
	Group1Garbage = [5/5/3]
	Group1Avid = [5/2/1..15/6/3]
	Group1Times = [2/2/1..6/5/3]

	Group2Mnemonics = ROL, ROR, RCL, SHL, RCR, SHR, MOVZX, MOVSX
	Group2Garbage = [4/3/2]
	Group2Avid = [4/2/1..8/4/2]
	Group2Times = [1..4/3/2]

	Group3Mnemonics = CMP, TEST, DEC, INC, NOT, NEG
	Group3Garbage = [5/4/2]
	Group3Avid = [4/2/1..10/5/3]
	Group3Times = [1..4/4/2]

	Group4Mnemonics = IMUL, LODSB, LODSW, LODSD, SCASB, SCASW, SCASD, CMPSB, CMPSW, CMPSD, STOSB, STOSW, STOSD, MOVSB, MOVSW, MOVSD, PUSHFD, POPFD
	Group4Garbage = [4/2/2]
	Group4Avid = [4/2/1..10/5/3]
	Group4Times = [1..3/2/2]

	Group5Mnemonics = JCC_INSIDE, JUMP_OUTSIDE, JUMP_INSIDE, CALL, UNDEF, RET, JCC_OUTSIDE
	Group5Garbage = [5/5/3]
	Group5Avid = [0..0]
	Group5Times = [3/2/1..7/5/3]
*/

#endif