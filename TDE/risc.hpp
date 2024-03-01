#ifndef RISC_HPP_
#define RISC_HPP_

#include "oreans_base.hpp"

class risc : public oreans_base
{
public:
	bool is_signature(instruction_container& vm_entrance);
	bool devirtualize(uint32_t vm_function, uint32_t vm_entry, instruction_container& vm_entrance);
};

/* 
	Machine: RISC32 (deprecated)

	[Main Machine Info]
	Name = (deprecated)
	MachineId =  0x00000200
	MachineSignature = 0x1ADCC45F
	ProductSupport = WinLicense, Themida
	FileVersionEncoded = 0x12872829
	HardwareEncryption = Not available

	[Main Machine Architecture]
	Name = RISC32
	Bits = 32
	MaxCPUs = 1
	Emulates = IA32

	[Main Machine Stats]
	MemoryUsage = 1000 KB
	Speed = 15
	Complexity = 40
	ScoreMultiplier = 1
*/

#endif