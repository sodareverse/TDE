#include "fish_handler.hpp"
#include "fish_handler_types.hpp"

#include "instruction_emulator.hpp"

#include <idp.hpp>

#define operand_prefix 0x66

fish_handler::fish_handler(uint16_t index)
	: wild_handler(index)
{

}

bool fish_handler::update_argument_data(fish_context& context)
{
	if (this->id != WILD_HANDLER_INVALID)
	{
		for (std::size_t i = 0; i < this->subhandlers.size() && i < this->x2.size(); i++)
		{
			if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_DATA)
			{
				if (this->x2.at(i).first == context.fish_operands[0].operand_data)
					this->x2.at(i).first = 0;
				else if (this->x2.at(i).first == context.fish_operands[1].operand_data)
					this->x2.at(i).first = 1;
				else
				{
					msg("Failed parsing argument data at %04X (%04X) with arg: %08X\n", this->id, this->index, this->x2.at(i).first);
					return false;
				}
			}
			else if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_INFO)
			{
				if (this->x2.at(i).first == context.fish_operands[0].operand_info)
					this->x2.at(i).first = 0;
				else if (this->x2.at(i).first == context.fish_operands[1].operand_info)
					this->x2.at(i).first = 1;
				else
				{
					msg("Failed parsing argument data at %04X (%04X) with arg: %08X\n", this->id, this->index, this->x2.at(i).first);
					return false;
				}
			}
		}
	}

	return true;
}

bool fish_handler::map_handler_specific(instruction_container& instructions, wild_context& context)
{
	try
	{
		return this->map_handler_fish(instructions, dynamic_cast<fish_context&>(context));
	}
	catch (std::bad_cast const& e)
	{
		msg("Exception: %s\n", e.what());
	}

	return false;
}

bool fish_handler::map_handler_fish(instruction_container& instructions, fish_context& context)
{
	if (!this->map_handler_call(instructions, context))
	{
		std::size_t offset = 0;

		while (this->map_subhandler(instructions, context, offset) &&
			this->subhandlers.back().first != FISH_SUBHANDLER_LOAD_STORE)
		{
			offset += this->subhandlers.back().second;
		}

		uint16_t subhandler_counter[FISH_SUBHANDLER_COUNT];
		memset(subhandler_counter, 0, sizeof(subhandler_counter));

		for (std::size_t i = 0; i < this->subhandlers.size(); i++)
		{
			if (this->subhandlers.at(i).first < FISH_SUBHANDLER_COUNT)
				subhandler_counter[this->subhandlers.at(i).first]++;
		}

		if (this->map_handler_internal_0000(instructions, context, subhandler_counter) ||
			this->map_handler_internal_0001(instructions, context, subhandler_counter) ||
			this->map_handler_internal_0002(instructions, context, subhandler_counter) ||
			this->map_handler_internal_0003(instructions, context, subhandler_counter) ||
			this->map_handler_internal_0004(instructions, context, subhandler_counter))
		{
			if (this->decrypt_fish_data(instructions, context))
				return true;
		}
		
		msg("[CodeDevirtualizer] Failed to either map- or decrypt handler data for handler %04X (%04X) of type fish.\n", this->index, this->id);
	}
	
	return true;
}

bool fish_handler::map_handler_call(instruction_container& instructions, wild_context& context)
{
	if (instructions.bounds(0, 20) &&
		instructions.at(0).is_mnemonic(UD_Imov) &&
		instructions.at(1).is_mnemonic(UD_Iadd) &&
		instructions.at(2).is_mnemonic(UD_Imov) &&
		instructions.at(3).is_mnemonic(UD_Icmp) &&
		instructions.at(4).is_mnemonic(UD_Ijnz) &&
		instructions.at(5).is_mnemonic(UD_Imov) &&
		instructions.at(6).is_mnemonic(UD_Iadd) &&
		instructions.at(7).is_mnemonic(UD_Imov) &&
		instructions.at(8).is_mnemonic(UD_Iadd) &&
		instructions.at(9).is_mnemonic(UD_Imov) &&
		instructions.at(10).is_mnemonic(UD_Iadd) &&
		instructions.at(11).is_mnemonic(UD_Imov) &&
		instructions.at(12).is_mnemonic(UD_Iadd) &&
		instructions.at(13).is_mnemonic(UD_Imov) &&
		instructions.at(14).is_mnemonic(UD_Icmp) &&
		instructions.at(15).is_mnemonic(UD_Ijz) &&
		instructions.at(16).is_mnemonic(UD_Icmp) &&
		instructions.at(17).is_mnemonic(UD_Ijz) &&
		instructions.at(18).is_mnemonic(UD_Iadd) &&
		instructions.at(19).is_mnemonic(UD_Imov) &&
		instructions.at(20).is_mnemonic(UD_Iadd))
	{
		this->id = WILD_HANDLER_CALL;
		this->opcode_offsets[0] = instructions.at(1).get_loword(1);
		this->opcode_offsets[1] = instructions.at(6).get_loword(1);
		this->opcode_offsets[2] = instructions.at(10).get_loword(1);
		this->opcode_offsets[3] = instructions.at(20).get_loword(1);
		this->opcode_offsets[4] = instructions.at(3).get_loword(1);
		this->opcode_offsets[5] = instructions.at(14).get_loword(1);
		this->opcode_offsets[6] = instructions.at(16).get_loword(1);
		return true;
	}

	return false;
}

bool fish_handler::map_handler_internal_0000(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts)
{
	if (instructions.size() >= 6 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0000] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_STORE] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0004] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_INFO] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_DATA] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_MNEMONIC] == 1)
	{
		this->id = FISH_HANDLER_PUSH_POP;

		if (!context.fish_operands[0].is_found)
		{
			for (std::size_t i = 0, offset = 0; i < this->subhandlers.size(); i++)
			{
				if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_INFO)
				{
					if (instructions.bounds(offset, 9))
						context.fish_operands[0].operand_info = instructions.at(offset + 9).get_operand_data<uint16_t>(0);
				}
				else if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_DATA)
				{
					if (instructions.bounds(offset, 5))
						context.fish_operands[0].operand_data = instructions.at(offset + 5).get_operand_data<uint16_t>(0);
				}

				offset += this->subhandlers.at(i).second;
			}

			context.fish_operands[0].is_found = true;
		}

		return true;
	}

	return false;
}

bool fish_handler::map_handler_internal_0001(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts)
{
	std::size_t index = 10;

	if (instructions.size() >= 5 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0000] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0001] == 0 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_STORE] == 0 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0004] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0005] == 0 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_INFO] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_DATA] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_MNEMONIC] == 1 &&
		instructions.find_mnemonic_index(UD_Ipushfd, index))
	{
		this->id = FISH_HANDLER_COMMON_UNARY_OPERATION;
		return true;
	}

	return false;
}
	
bool fish_handler::map_handler_internal_0002(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts)
{
	if (instructions.size() >= 10 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0000] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0001] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_STORE] == 0 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0004] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0005] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_INFO] == 2 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_DATA] == 2 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_MNEMONIC] == 1)
	{
		this->id = FISH_HANDLER_COMMON_BINARY_OPERATION;
		
		if (context.fish_operands[0].is_found && !context.fish_operands[1].is_found)
		{
			for (std::size_t i = 0, offset = 0; i < this->subhandlers.size(); i++)
			{
				if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_INFO)
				{
					if (instructions.bounds(offset, 9) &&
						instructions.at(offset + 9).is_operand_data_not<uint16_t>(0, context.fish_operands[0].operand_info))
					{
						context.fish_operands[1].operand_info = instructions.at(offset + 9).get_operand_data<uint16_t>(0);
					}
				}
				else if (this->subhandlers.at(i).first == FISH_SUBHANDLER_LOAD_OPERAND_DATA)
				{
					if (instructions.bounds(offset, 5) &&
						instructions.at(offset + 5).is_operand_data_not<uint16_t>(0, context.fish_operands[0].operand_data))
					{
						context.fish_operands[1].operand_data = instructions.at(offset + 5).get_operand_data<uint16_t>(0);
					}
				}

				offset += this->subhandlers.at(i).second;
			}

			context.fish_operands[1].is_found = true;
		}

		return true;
	}

	return false;
}
	
bool fish_handler::map_handler_internal_0003(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts)
{
	if (instructions.size() >= 2 &&
		subhandler_counts[FISH_SUBHANDLER_ALIGN_REGISTER] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_DATA] == 1)
	{
		this->id = FISH_HANDLER_ALIGN;
		return true;
	}

	return false;
}
	
bool fish_handler::map_handler_internal_0004(instruction_container& instructions, fish_context& context, uint16_t* subhandler_counts)
{
	if (instructions.size() >= 8 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0000] == 1 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0001] == 0 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0002] == 1 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_STORE] == 0 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0004] == 2 &&
		subhandler_counts[FISH_UNKNOWN_SUBHANDLER_0005] == 0 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_INFO] == 2 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_OPERAND_DATA] == 2 &&
		subhandler_counts[FISH_SUBHANDLER_LOAD_MNEMONIC] == 0)
	{
		this->id = FISH_HANDLER_XCHG;
		return true;
	}

	return false;
}

bool fish_handler::map_subhandler(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	return (this->map_subhandler_0000(instructions, context, offset) ||
		this->map_subhandler_0001(instructions, context, offset) ||
		this->map_subhandler_0002(instructions, context, offset) ||
		this->map_subhandler_0003(instructions, context, offset) ||
		this->map_subhandler_0004(instructions, context, offset) ||
		this->map_subhandler_0005(instructions, context, offset) ||
		this->map_subhandler_0006(instructions, context, offset) ||
		this->map_subhandler_0007(instructions, context, offset) ||
		this->map_subhandler_0008(instructions, context, offset) ||
		this->map_subhandler_0009(instructions, context, offset) ||
		this->map_subhandler_000A(instructions, context, offset));
}

bool fish_handler::map_subhandler_0000(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 27;

	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 8).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 9).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 10).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 13).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 14).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 15).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 16).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 17).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 18).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 19).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 20).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 21).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 22).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 23).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 24).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 25).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 26).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0000, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0001(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 24;
	
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 8).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 9).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 10).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 13).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 14).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 15).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 16).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 17).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 18).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 19).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 20).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 21).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 22).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 23).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0001, subhandler_size));
		return true;
	}
	else if (instructions.bounds(offset, subhandler_size - 3) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 7).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 8).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 9).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 10).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 11).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 12).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 13).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 14).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 15).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 16).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 17).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 18).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 19).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 20).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 21).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0001, subhandler_size - 2));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0002(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 27;
	
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 8).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 9).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 10).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 13).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 14).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 15).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 16).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 17).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 18).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 19).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 20).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 21).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 22).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 23).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 24).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 25).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 26).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0002, subhandler_size));
		return true;
	}
	else if (instructions.bounds(offset, subhandler_size - 3) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 7).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 8).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 9).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 10).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 13).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 14).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 15).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 16).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 17).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 18).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 19).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 20).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 21).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 22).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 23).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 24).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0002, subhandler_size - 2));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0003(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	/*
		decode idk3/idk5 -> $1
		decode key (byte) -> $2
		decode operand size -> $3

		push:
		compare $2 to FISH_MNEMONIC_PUSH (else: skip 'push')
		compare $3 to 0x2 (if: push word $1, else: push dword $1)

		pop:
		compare $2 to FISH_MNEMONIC_POP (else: skip 'pop')
		decode VM_REG -> $1
		compare $3 to 0x2 (if: pop word ptr [$1], else: pop dword ptr [$1])
	*/
	if (instructions.bounds(offset, 3) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 3).is_mnemonic(UD_Imov))
	{
		std::size_t index = offset + 3;

		ud_type bases[2] = { UD_NONE, UD_NONE };

		for (std::size_t i = 0; i < 2; i++)
		{
			if (instructions.bounds(index) &&
				instructions.at(index).is_mnemonic(UD_Imov) &&
				instructions.at(index).is_operand_type(0, UD_OP_REG))
			{ 
				bases[i] = instructions.at(index++).get_base_type(0);

				while (instructions.bounds(index) &&
					instructions.at(index).is_mnemonic_not(UD_Imov) &&
					instructions.at(index).is_mnemonic_not(UD_Icmp) &&
					instructions.at(index).is_operand_base(0, { bases[0], bases[1] }))
				{
					index++;
				}
			}
		}

		if (instructions.bounds(index, 4) &&
			instructions.at(index).is_mnemonic(UD_Icmp) &&
			instructions.at(index + 1).is_mnemonic(UD_Ijnz) &&
			instructions.at(index + 2).is_mnemonic(UD_Icmp) &&
			instructions.at(index + 3).is_mnemonic(UD_Ijnz) &&
			instructions.at(index + 4).is_mnemonic(UD_Ipush))
		{
			index += 5;
			
			if (instructions.bounds(index) &&
				instructions.at(index).is_mnemonic(UD_Imov) &&
				instructions.at(index).is_operand_type(0, UD_OP_REG))
			{
				ud_type base = instructions.at(index++).get_base_type(0);
				
				while (instructions.bounds(index) &&
					instructions.at(index).is_mnemonic_not(UD_Imov) &&
					instructions.at(index).is_mnemonic_not(UD_Icmp) &&
					instructions.at(index).is_operand_base(0, base))
				{
					index++;
				}
			}
			
			if (instructions.bounds(index, 6) &&
				instructions.at(index).is_mnemonic(UD_Icmp) &&
				instructions.at(index + 1).is_mnemonic(UD_Ijnz) &&
				instructions.at(index + 2).is_mnemonic(UD_Imov) &&
				instructions.at(index + 3).compare_mnemonic(false, false, true) &&
				instructions.at(index + 4).is_mnemonic(UD_Icmp) &&
				instructions.at(index + 5).is_mnemonic(UD_Ijnz) &&
				instructions.at(index + 6).is_mnemonic(UD_Ipop))
			{
				this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_LOAD_STORE, index + 7));
				return true;
			}
		}
	}

	return false;
}

bool fish_handler::map_subhandler_0004(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 16;
	
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 8).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 9).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 10).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 13).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 14).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 15).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0004, subhandler_size));
		return true;
	}
	else if (instructions.bounds(offset, subhandler_size - 3) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 8).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 9).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 10).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 11).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 12).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 13).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0004, subhandler_size - 2));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0005(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 13;
	
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 8).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 9).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 10).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 11).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 12).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0005, subhandler_size));
		return true;
	}
	else if (instructions.bounds(offset, subhandler_size - 3) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).is_mnemonic(UD_Icmp) &&
		instructions.at(offset + 3).is_mnemonic(UD_Ijnz) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 7).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 8).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 9).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 10).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_UNKNOWN_SUBHANDLER_0005, subhandler_size - 2));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0006(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 11;
	
	/* 
		read opcode (byte) -> $1
		encode (($1 & 0xF0) >> 4) -> idk4/idk6	; operand type (1 = register, 2 = memory, 3 = immediate)
		encode ($1 & 0xF) -> 0x70/0x3A			; operand size (1 = byte, 2 = word, 3 = dword)
	*/
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 2).is_mnemonic(UD_Imovzx) &&
		instructions.at(offset + 3).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 4).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 5).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 6).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 7).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 8).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 9).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 10).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_LOAD_OPERAND_INFO, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0007(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 7;
	
	/*
		decode idk3/idk5 -> $1
		and $1,0xFFFF
		add $1,VM_CONTEXT
		add dword ptr [$1],imagebase
	*/
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 2).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 3).is_mnemonic(UD_Iand) &&
		instructions.at(offset + 4).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 5).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 5).is_operand_type(1, UD_OP_MEM, UD_SIZE_DWORD) &&
		instructions.at(offset + 5).is_operand_data(1, context.vm_imagebase_offset) &&
		instructions.at(offset + 6).is_mnemonic(UD_Iadd))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_ALIGN_REGISTER, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0008(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 6;
	
	/*
		read opcode (dword) -> $1
		encode $1 -> idk3/idk5
	*/
	if (instructions.bounds(offset, subhandler_size - 2) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 2).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 3).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 4).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_LOAD_OPERAND_DATA, subhandler_size - 1));
		return true;
	}
	else if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 1).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 2).is_mnemonic(UD_Imov) &&
		instructions.at(offset + 3).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 4).compare_mnemonic(false, false, true) &&
		instructions.at(offset + 5).is_mnemonic(UD_Imov))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_LOAD_OPERAND_DATA, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_0009(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 3;

	/*
		read opcode (byte) -> $1
		encode $1 -> key (byte)
	*/
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		context.is_opcode_access_instruction(instructions.at(offset)) &&
		instructions.at(offset + 1).is_mnemonic(UD_Iadd) &&
		instructions.at(offset + 2).is_mnemonic(UD_Imovzx) &&
		instructions.at(offset + 2).is_operand_type(1, UD_OP_MEM, UD_SIZE_BYTE))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_LOAD_MNEMONIC, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::map_subhandler_000A(instruction_container& instructions, fish_context& context, std::size_t& offset)
{
	const std::size_t subhandler_size = 1;

	/* 0: mov byte ptr [ebp+xx],0x00 */
	if (instructions.bounds(offset, subhandler_size - 1) &&
		instructions.at(offset).is_mnemonic(UD_Imov) &&
		instructions.at(offset).is_operand_type(0, UD_OP_MEM, UD_SIZE_BYTE) &&
		instructions.at(offset).is_operand_base(0, UD_R_EBP) &&
		instructions.at(offset).has_operand_index_not(0) &&
		instructions.at(offset).has_operand_scale_not(0) &&
		instructions.at(offset).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE) &&
		instructions.at(offset).is_operand_data(1, 0))
	{
		this->subhandlers.push_back(std::make_pair(FISH_SUBHANDLER_RESET_INTERNAL_STATE, subhandler_size));
		return true;
	}
	
	return false;
}

bool fish_handler::decrypt_default_data(instruction_container& instructions, wild_context& context)
{
	return true;
}

bool fish_handler::decrypt_fish_data(instruction_container& instructions, fish_context& context)
{
	for (std::size_t i = 0, offset = 0, push_pop_subhandler_offset = 0, parameter_count = 0;; i++)
	{
		if (i >= this->subhandlers.size())
		{
			if (this->id == FISH_HANDLER_PUSH_POP)
				return this->parse_push_pop_mnemonics(instructions, context, push_pop_subhandler_offset);
			else if (this->id == FISH_HANDLER_COMMON_UNARY_OPERATION)
				return this->parse_unary_operation_mnemonics(instructions, context, offset);
			else if (this->id == FISH_HANDLER_COMMON_BINARY_OPERATION)
				return this->parse_binary_operation_mnemonics(instructions, context, offset);
			else
				return true;
		}
		else
		{
			switch (this->subhandlers.at(i).first)
			{
			case FISH_UNKNOWN_SUBHANDLER_0000:
			case FISH_UNKNOWN_SUBHANDLER_0001:
			case FISH_UNKNOWN_SUBHANDLER_0002:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 2).get_loword(1);
				this->x2.push_back(std::make_pair(0xFF, instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_LOAD_STORE:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 4).get_loword(1);
				this->x2.push_back(std::make_pair(0xFF, instructions.at(offset + 4).get_index()));
				push_pop_subhandler_offset = offset;
				break;

			case FISH_UNKNOWN_SUBHANDLER_0004:
			case FISH_UNKNOWN_SUBHANDLER_0005:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 2).get_loword(1);
				this->x2.push_back(std::make_pair(0xFF, instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_LOAD_OPERAND_INFO:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 1).get_loword(1);
				this->x2.push_back(std::make_pair(instructions.at(offset + 9).get_operand_data<uint8_t>(0), instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_ALIGN_REGISTER:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 1).get_loword(1);
				this->x2.push_back(std::make_pair(0xFF, instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 1).get_loword(1);
				this->x2.push_back(std::make_pair(instructions.at(offset + (this->subhandlers.at(i).second - 1)).get_operand_data<uint8_t>(0), instructions.at(offset + 2).get_index()));
				//this->x2.push_back(std::make_pair(instructions.at(offset + 5).get_operand_data<uint8_t>(0), instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_LOAD_MNEMONIC:
				this->opcode_offsets[parameter_count++] = instructions.at(offset + 1).get_loword(1);
				this->x2.push_back(std::make_pair(0xFF, instructions.at(offset + 2).get_index()));
				break;

			case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
				this->opcode_offsets[parameter_count++] = instructions.at(offset).get_loword(1);
				this->x2.push_back(std::make_pair(0x00, instructions.at(offset).get_index()));
				break;

			default:
				return false;
			}

			offset += this->subhandlers.at(i).second;
		}
	}

	return false;
}

bool fish_handler::parse_push_pop_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index)
{
	ud_instruction mnemonic_key_instruction;
	
	if (!this->find_mnemonic_key_read_instruction(instructions, context, index, mnemonic_key_instruction))
		return false;
	
	/* 0: ___ reg,imm8 */
	while (instructions.bounds(++index) &&
		instructions.at(index).is_mnemonic_not(UD_Icmp))
	{
		if (instructions.at(index).compare_mnemonic(false, false, true) &&
			instructions.at(index).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0) &&
			instructions.at(index).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE))
		{
			this->mnemonic_key_decoders.push_back(std::make_pair(instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_data<uint8_t>(1)));
		}
	}
	
	if (instructions.at(index).is_mnemonic(UD_Icmp) &&
		instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0))
	{
		if (!context.initialized_push_pop_mnemonics)
		{
			if (instructions.at(index).is_operand_data(1, 0))
			{
				context.set_mnemonic(this->mnemonic_key_decoders.back().second, UD_Ipush);
				this->mnemonic_key_decoders.pop_back();
				
				for (int i = 0; i < 2; i++)
				{
					if (!instructions.find_mnemonic_index(UD_Icmp, ++index))
						return false;
				}
				
				context.set_mnemonic(instructions.at(index - 1).get_operand_data<uint8_t>(1), UD_Ipop);
			}
			else
			{
				context.set_mnemonic(instructions.at(index).get_operand_data(1), UD_Ipush);

				for (int i = 0; i < 2; i++)
				{
					if (!instructions.find_mnemonic_index(UD_Icmp, ++index))
						return false;
				}
				
				context.set_mnemonic(instructions.at(index).get_operand_data(1), UD_Ipop);
			}
			
			context.initialized_push_pop_mnemonics = true;
		}
		else if (instructions.at(index).is_operand_data(1, 0))
		{
			this->mnemonic_key_decoders.pop_back();
		}

		return true;
	}
	
	return false;
}

bool fish_handler::parse_unary_operation_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index)
{
	ud_instruction mnemonic_key_instruction;

	if (context.initialized_unary_mnemonics)
	{
		if (!this->find_mnemonic_key_read_instruction(instructions, context, index, mnemonic_key_instruction))
			return false;
	
		/* 0: ___ reg,imm8 */
		while (instructions.bounds(++index) &&
			instructions.at(index).is_mnemonic_not(UD_Icmp))
		{
			if (instructions.at(index).compare_mnemonic(false, false, true) &&
				instructions.at(index).is_operand_type(0, UD_OP_REG) &&
				instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0) &&
				instructions.at(index).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE))
			{
				this->mnemonic_key_decoders.push_back(std::make_pair(instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_data<uint8_t>(1)));
			}
		}

		if (instructions.at(index).is_mnemonic(UD_Icmp))
		{
			if (instructions.at(index).is_operand_data(1, 0))
				this->mnemonic_key_decoders.pop_back();

			return true;
		}
	}
	else
	{
		for (std::size_t i = 0; i < 4; i++)
		{
			if (!this->find_mnemonic_key_read_instruction(instructions, context, index, mnemonic_key_instruction))
				return false;
	
			this->mnemonic_key_decoders.clear();

			/* 0: ___ reg,imm8 */
			while (instructions.bounds(++index) &&
				instructions.at(index).is_mnemonic_not(UD_Icmp))
			{
				if (instructions.at(index).compare_mnemonic(false, false, true) &&
					instructions.at(index).is_operand_type(0, UD_OP_REG) &&
					instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0) &&
					instructions.at(index).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE))
				{
					this->mnemonic_key_decoders.push_back(std::make_pair(instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_data<uint8_t>(1)));
				}
			}
			
			if (instructions.at(index).is_mnemonic_not(UD_Icmp))
				return false;
			
			uint8_t mnemonic_id = 0;
			
			if (instructions.at(index).is_operand_data(1, 0))
			{
				mnemonic_id = this->mnemonic_key_decoders.back().second;
				this->mnemonic_key_decoders.pop_back();
			}
			else
			{
				mnemonic_id = instructions.at(index).get_operand_data<uint8_t>(1);
			}
			
			if (!this->parse_handler_mnemonic(instructions, context, ++index, mnemonic_id))
				return false;
		}

		context.initialized_unary_mnemonics = true;
		return true;
	}

	return false;
}

bool fish_handler::parse_binary_operation_mnemonics(instruction_container& instructions, fish_context& context, std::size_t index)
{
	ud_instruction mnemonic_key_instruction;

	if (context.initialized_binary_mnemonics)
	{
		if (!this->find_mnemonic_key_read_instruction(instructions, context, index, mnemonic_key_instruction))
			return false;
	
		/* 0: ___ reg,imm8 */
		while (instructions.bounds(++index) &&
			instructions.at(index).is_mnemonic_not(UD_Icmp))
		{
			if (instructions.at(index).compare_mnemonic(false, false, true) &&
				instructions.at(index).is_operand_type(0, UD_OP_REG) &&
				instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0) &&
				instructions.at(index).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE))
			{
				this->mnemonic_key_decoders.push_back(std::make_pair(instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_data<uint8_t>(1)));
			}
		}

		if (instructions.at(index).is_mnemonic(UD_Icmp))
		{
			if (instructions.at(index).is_operand_data(1, 0))
				this->mnemonic_key_decoders.pop_back();

			return true;
		}
	}
	else
	{
		for (std::size_t i = 0; i < 17; i++)
		{
			if (!this->find_mnemonic_key_read_instruction(instructions, context, index, mnemonic_key_instruction))
				return false;
	
			this->mnemonic_key_decoders.clear();

			/* 0: ___ reg,imm8 */
			while (instructions.bounds(++index) &&
				instructions.at(index).is_mnemonic_not(UD_Icmp))
			{
				if (instructions.at(index).compare_mnemonic(false, false, true) &&
					instructions.at(index).is_operand_type(0, UD_OP_REG) &&
					instructions.at(index).is_operand_base(0, mnemonic_key_instruction, 0) &&
					instructions.at(index).is_operand_type(1, UD_OP_IMM, UD_SIZE_BYTE))
				{
					this->mnemonic_key_decoders.push_back(std::make_pair(instructions.at(index).get_mnemonic(), instructions.at(index).get_operand_data<uint8_t>(1)));
				}
			}
			
			if (instructions.at(index).is_mnemonic_not(UD_Icmp))
				return false;
			
			uint8_t mnemonic_id = 0;
			
			if (instructions.at(index).is_operand_data(1, 0))
			{
				mnemonic_id = this->mnemonic_key_decoders.back().second;
				this->mnemonic_key_decoders.pop_back();
			}
			else
			{
				mnemonic_id = instructions.at(index).get_operand_data<uint8_t>(1);
			}
			
			if (!this->parse_handler_mnemonic(instructions, context, ++index, mnemonic_id))
				return false;
		}

		context.initialized_binary_mnemonics = true;
		return true;
	}

	return false;
}

bool fish_handler::parse_handler_mnemonic(instruction_container& instructions, fish_context& context, std::size_t& index, uint8_t offset)
{
	std::size_t temp_index = index;
	
	/* 0: jnz ___ */
	if (!instructions.find_mnemonic_index(UD_Ijnz, temp_index))
		return false;
	
	/* 0: pushfd */
	if (!instructions.find_mnemonic_index(UD_Ipushfd, temp_index))
		return false;

	index = temp_index;
	
	if (this->id == FISH_HANDLER_COMMON_UNARY_OPERATION && 
		instructions.at(index - 2).is_mnemonic(UD_Inot) &&
		instructions.at(index - 1).is_mnemonic(UD_Icmp))
	{
		context.set_mnemonic(offset, UD_Inot);
		return true;
	}
	else if (this->id == FISH_HANDLER_COMMON_BINARY_OPERATION && 
		instructions.at(index - 1).is_mnemonic(UD_Iadd))
	{
		if (instructions.at(index - 2).is_mnemonic(UD_Imov) &&
			instructions.at(index - 2).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base(0, instructions.at(index - 1), 1) &&
			instructions.at(index - 2).is_operand_type(1, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base(1, instructions.at(index - 1), 0))
		{
			context.set_mnemonic(offset, UD_Imovspecial);
			return true;
		}
		else if (instructions.at(index - 2).is_mnemonic(UD_Imovsx) &&
			instructions.at(index - 2).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base(0, instructions.at(index - 1), 1) &&
			instructions.at(index - 2).is_operand_type(1, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base_family(1, instructions.at(index - 1).get_base_type(0)))
		{
			context.set_mnemonic(offset, UD_Imovsx);
			return true;
		}
		else if (instructions.at(index - 2).is_mnemonic(UD_Imovzx) &&
			instructions.at(index - 2).is_operand_type(0, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base(0, instructions.at(index - 1), 1) &&
			instructions.at(index - 2).is_operand_type(1, UD_OP_REG) &&
			instructions.at(index - 2).is_operand_base_family(1, instructions.at(index - 1).get_base_type(0)))
		{
			context.set_mnemonic(offset, UD_Imovzx);
			return true;
		}
	}
	
	context.set_mnemonic(offset, instructions.at(index - 1).get_mnemonic());
	return true;
}

bool fish_handler::find_mnemonic_key_read_instruction(instruction_container& instructions, fish_context& context, std::size_t& index, ud_instruction& instruction)
{
	for (std::size_t i = index; i < instructions.size(); i++)
	{
		/* 0: mov reg,byte ptr [ebp+xx] */
		if (instructions.at(i).is_mnemonic(UD_Imov) &&
			instructions.at(i).is_operand_type(0, UD_OP_REG) &&
			instructions.at(i).is_operand_type(1, UD_OP_MEM, UD_SIZE_BYTE) &&
			instructions.at(i).is_operand_base(1, UD_R_EBP) &&
			instructions.at(i).has_operand_index_not(1) &&
			instructions.at(i).has_operand_scale_not(1) &&
			instructions.at(i).is_operand_data(1, context.get_key_offset(FISH_KEY_MNEMONIC)))
		{
			index = i;
			instruction = instructions.at(i);
			return true;
		}
	}

	return false;
}

bool fish_handler::step_handler_specific(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	try
	{
		return this->step_handler_fish(instructions, dynamic_cast<fish_context&>(context), opcode);
	}
	catch (std::bad_cast const& e)
	{
		msg("[CodeDevirtualizer] Exception: %s\n", e.what());
	}

	return false;
}

bool fish_handler::step_handler_fish(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	switch (this->id)
	{
	case WILD_HANDLER_CALL:
		return this->step_handler_call(instructions, context, opcode);

	case FISH_HANDLER_PUSH_POP:
		return this->step_handler_push_pop(instructions, context, opcode);

	case FISH_HANDLER_COMMON_UNARY_OPERATION:
		return this->step_handler_common_unary_operation(instructions, context, opcode);

	case FISH_HANDLER_COMMON_BINARY_OPERATION:
		return this->step_handler_common_binary_operation(instructions, context, opcode);

	case FISH_HANDLER_ALIGN:
		return this->step_handler_align(instructions, context, opcode);

	case FISH_HANDLER_XCHG:
		return this->step_handler_xchg(instructions, context, opcode);

	default:
		break;
	}

	return false;
}

bool fish_handler::step_handler_call(instruction_container& instructions, wild_context& context, opcode_reader& opcode)
{
	uint32_t type = opcode.read<uint8_t>(this->opcode_offsets[0]);
	
	context.step_params[0] = type;
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Icall);

	if (type == this->opcode_offsets[4])
	{
		uint32_t offset = opcode.read<uint32_t>(this->opcode_offsets[1]);

		instruction.set_operand_type(0, UD_OP_IMM, UD_SIZE_DWORD);
		instruction.set_operand_data(0, context.vm_imagebase + offset);
	}
	else if (type == this->opcode_offsets[5])
	{
		uint32_t register_id = opcode.read<uint8_t>(this->opcode_offsets[1]);

		instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
		instruction.set_operand_base(0, context.get_vm_register(register_id));
	}
	else if (type == this->opcode_offsets[6])
	{
		uint32_t register_id = opcode.read<uint8_t>(this->opcode_offsets[1]);

		instruction.set_operand_type(0, UD_OP_MEM, UD_SIZE_DWORD);
		instruction.set_operand_base(0, context.get_vm_register(register_id));
	}

	instructions.push_back(instruction);

	/* Decode return address and create label */
	uint32_t return_address = context.vm_imagebase + opcode.read<uint32_t>(this->opcode_offsets[3]);
	
	if (!return_address)
		return false;

	ud_instruction return_instruction(return_address);
	return_instruction.set_input(context.to_segment(return_address));
	
	instruction_container return_instructions;
	
	for (std::size_t i = 0; i < 2; i++)
	{
		if (!return_instructions.decode_assembly(return_instruction))
			return false;

		if (return_instruction.is_mnemonic_not(UD_Ipush) ||
			return_instruction.is_operand_type_not(0, UD_OP_IMM, UD_SIZE_DWORD))
		{
			return false;
		}
	}
	
	context.create_label(context.vm_imagebase + return_instructions.at(0).get_operand_data(0), return_instructions.at(1).get_operand_data(0));
	return true;
}

bool fish_handler::step_handler_push_pop(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < 3)
		this->perform_key_sequence(context, 0, this->x2.at(0).second, &key_data);
	
	uint32_t operand_info = 0;
	uint32_t operand_data = 0;

	for (std::size_t i = 0; i < this->subhandlers.size(); i++)
	{
		switch (this->subhandlers.at(i).first)
		{
		case 0:
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;

		case 3:
			this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);
			break;

		case 4:
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_INFO:
			operand_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_info);
			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
			operand_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_data);
			break;
			
		case 9:
			key_data = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;

		case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;

		default:
			break;
		}
	}
	
	context.step_params[0] = context.get_key_data(FISH_KEY_MNEMONIC);

	for (std::size_t i = 0; i < this->mnemonic_key_decoders.size(); i++)
		instruction::emulate(this->mnemonic_key_decoders.at(i).first, UD_SIZE_BYTE, this->mnemonic_key_decoders.at(i).second, &context.step_params[0]);

	context.step_params[1] = operand_info;
	context.step_params[2] = operand_data;

	if (context.current_register_type < 0)
	{
		this->parse_common_instruction(instructions, context, context.current_virtual_opcode,
			context.get_key_data(FISH_KEY_MNEMONIC), operand_info, operand_data, 0, 0);
	}
	else
	{
		ud_type base = static_cast<ud_type>(UD_R_EAX + context.current_register_type--);

		ud_instruction instruction(context.current_virtual_opcode);
		instruction.set_mnemonic(UD_Ipop);
		instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
		instruction.set_operand_base(0, base);

		if (base != UD_R_ESP)
			context.set_vm_register(operand_data, base);

		instructions.push_back(instruction);
	}

	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool fish_handler::step_handler_common_unary_operation(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < 3)
		this->perform_key_sequence(context, 0, this->x2.at(0).second, &key_data);

	uint32_t operand_info = 0;
	uint32_t operand_data = 0;
	
	for (std::size_t i = 0; i < this->subhandlers.size(); i++)
	{
		switch (this->subhandlers.at(i).first)
		{
		case 0:
		case 1:
		case 2:
		case 4:
		case 5:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_INFO:
			operand_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_info);
			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
			operand_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_data);
			break;
			
		case 9:
			key_data = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;

		case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;

		default:
			break;
		}
	}

	context.step_params[0] = context.get_key_data(FISH_KEY_MNEMONIC);

	for (std::size_t i = 0; i < this->mnemonic_key_decoders.size(); i++)
		instruction::emulate(this->mnemonic_key_decoders.at(i).first, UD_SIZE_BYTE, this->mnemonic_key_decoders.at(i).second, &context.step_params[0]);
	
	//this->step_params[0] = this->fish_keys.get_data(FISH_KEY_MNEMONIC);
	//this->perform_immediate_action(static_cast<x86_mnemonic_code>(handler_object.mnemonic_key_decode_mnemonic), OPERAND_SIZE_BYTE, &this->step_params[0], handler_object.mnemonic_key_decode_data);

	context.step_params[1] = operand_info;
	context.step_params[2] = operand_data;
	
	this->parse_common_instruction(instructions, context, context.current_virtual_opcode,
		context.get_key_data(FISH_KEY_MNEMONIC), operand_info, operand_data, 0, 0);

	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool fish_handler::step_handler_common_binary_operation(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < 3)
		this->perform_key_sequence(context, 0, this->x2.at(0).second, &key_data);
	
	uint32_t operand_0_info = 0;
	uint32_t operand_0_data = 0;
	
	uint32_t operand_1_info = 0;
	uint32_t operand_1_data = 0;

	for (std::size_t i = 0; i < this->subhandlers.size(); i++)
	{
		switch (this->subhandlers.at(i).first)
		{
		case 0:
		case 1:
		case 2:
		case 4:
		case 5:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_INFO:
			if (this->x2.at(i).first == 0)
			{
				operand_0_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_0_info);
			}
			else if (this->x2.at(i).first == 1)
			{
				operand_1_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_1_info);
			}
			
			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
			if (this->x2.at(i).first == 0)
			{
				operand_0_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_0_data);
			}
			else if (this->x2.at(i).first == 1)
			{
				operand_1_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_1_data);
			}
			
			break;

		case 9:
			key_data = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;
			
		case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;

		default:
			break;
		}
	}

	context.step_params[0] = context.get_key_data(FISH_KEY_MNEMONIC);

	for (std::size_t i = 0; i < this->mnemonic_key_decoders.size(); i++)
		instruction::emulate(this->mnemonic_key_decoders.at(i).first, UD_SIZE_BYTE, this->mnemonic_key_decoders.at(i).second, &context.step_params[0]);
	
	//this->step_params[0] = this->fish_keys.get_data(FISH_KEY_MNEMONIC);
	//this->perform_immediate_action(static_cast<x86_mnemonic_code>(handler_object.mnemonic_key_decode_mnemonic), OPERAND_SIZE_BYTE, &this->step_params[0], handler_object.mnemonic_key_decode_data);
	
	context.step_params[1] = operand_0_info;
	context.step_params[2] = operand_0_data;
	context.step_params[3] = operand_1_info;
	context.step_params[4] = operand_1_data;
	
	this->parse_common_instruction(instructions, context, context.current_virtual_opcode, context.get_key_data(FISH_KEY_MNEMONIC), operand_0_info, operand_0_data, operand_1_info, operand_1_data);

	if (instructions.back().is_mnemonic(UD_Imov) &&
		instructions.back().is_operand_type(0, UD_OP_REG, UD_SIZE_BYTE) &&
		instructions.back().is_operand_base(0, UD_R_AL) &&
		instructions.back().is_operand_type(1, UD_OP_REG, UD_SIZE_BYTE) &&
		instructions.back().is_operand_base(1, UD_R_AL))
	{
		instructions.back().set_mnemonic(UD_Inop);
		instructions.back().set_operand_null(0);
		instructions.back().set_operand_null(1);
	}

	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool fish_handler::step_handler_align(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < 3)
		this->perform_key_sequence(context, 0, this->x2.at(0).second, &key_data);
	
	uint32_t register_id = 0;

	for (std::size_t i = 0; i < this->subhandlers.size(); i++)
	{
		switch (this->subhandlers.at(i).first)
		{
		case FISH_SUBHANDLER_ALIGN_REGISTER:
			this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);
			break;

		case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
			register_id = opcode.read<uint32_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &register_id);
			break;
			
		case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;

		default:
			break;
		}
	}

	context.step_params[0] = register_id;

	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(UD_Ialign);
	instruction.set_operand_type(0, UD_OP_REG, UD_SIZE_DWORD);
	instruction.set_operand_base(0, context.get_vm_register(register_id));
	instruction.set_operand_type(1, UD_OP_IMM, UD_SIZE_DWORD);
	instruction.set_operand_data(1, context.vm_imagebase);

	instructions.push_back(instruction);
	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool fish_handler::step_handler_xchg(instruction_container& instructions, fish_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;

	if (this->key_accessors.size() > 0 && this->key_accessors.at(0).index < 3)
		this->perform_key_sequence(context, 0, this->x2.at(0).second, &key_data);
	
	uint32_t operand_0_info = 0;
	uint32_t operand_0_data = 0;
	
	uint32_t operand_1_info = 0;
	uint32_t operand_1_data = 0;
	
	for (std::size_t i = 0; i < this->subhandlers.size(); i++)
	{
		switch (this->subhandlers.at(i).first)
		{
		case 0:
		case 1:
		case 2:
		case 4:
		case 5:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_INFO:
			if (this->x2.at(i).first == 0)
			{
				operand_0_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_0_info);
			}
			else if (this->x2.at(i).first == 1)
			{
				operand_1_info = opcode.read<uint8_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_1_info);
			}

			break;
			
		case FISH_SUBHANDLER_LOAD_OPERAND_DATA:
			if (this->x2.at(i).first == 0)
			{
				operand_0_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_0_data);
			}
			else if (this->x2.at(i).first == 1)
			{
				operand_1_data = opcode.read<uint32_t>(this->opcode_offsets[i]);
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &operand_1_data);
			}
			
			break;

		case 9:
			key_data = opcode.read<uint8_t>(this->opcode_offsets[i]);
			this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			break;
			
		case FISH_SUBHANDLER_RESET_INTERNAL_STATE:
			if ((i + 1) < this->subhandlers.size())
				this->perform_key_sequence(context, this->x2.at(i).second, this->x2.at(i + 1).second, &key_data);
			else
				this->perform_key_sequence(context, this->x2.at(i).second, this->flow_data_index, &key_data);

			break;

		default:
			break;
		}
	}

	context.step_params[0] = UD_Ixchg;

	for (std::size_t i = 0; i < this->mnemonic_key_decoders.size(); i++)
		instruction::emulate(this->mnemonic_key_decoders.at(i).first, UD_SIZE_BYTE, this->mnemonic_key_decoders.at(i).second, &context.step_params[0]);
	
	//this->step_params[0] = UD_Ixchg;
	//this->perform_immediate_action(static_cast<x86_mnemonic_code>(handler_object.mnemonic_key_decode_mnemonic), OPERAND_SIZE_BYTE, &this->step_params[0], handler_object.mnemonic_key_decode_data);
	
	context.step_params[1] = operand_0_info;
	context.step_params[2] = operand_0_data;
	context.step_params[3] = operand_1_info;
	context.step_params[4] = operand_1_data;
	
	this->parse_common_instruction(instructions, context, context.current_virtual_opcode, context.get_key_data(FISH_KEY_MNEMONIC), operand_0_info, operand_0_data, operand_1_info, operand_1_data);

	instructions.back().set_mnemonic(UD_Ixchg);

	return this->step_handler_flow(context, opcode.read<uint16_t>(this->flow_read_offset), false);
}

bool fish_handler::step_default_sequence(wild_context& context, opcode_reader& opcode)
{
	uint32_t key_data = 0;
	return this->perform_key_sequence(context, 0, this->flow_data_index, &key_data);
}

void fish_handler::parse_common_instruction(instruction_container& instructions, fish_context& context, uint32_t address, uint16_t mnemonic_key_constant, uint8_t operand_0_info, uint32_t operand_0_data, uint8_t operand_1_info, int32_t operand_1_data)
{
	uint32_t mnemonic_id = mnemonic_key_constant;

	for (std::size_t i = 0; i < this->mnemonic_key_decoders.size(); i++)
		instruction::emulate(this->mnemonic_key_decoders.at(i).first, UD_SIZE_BYTE, this->mnemonic_key_decoders.at(i).second, &mnemonic_id);
	
	ud_instruction instruction(context.current_virtual_opcode);
	instruction.set_mnemonic(context.get_mnemonic(mnemonic_id));

	uint8_t operand_0_type = static_cast<uint8_t>((operand_0_info >> 4) & 0xF);
	ud_size operand_0_size = static_cast<ud_size>(static_cast<uint8_t>(std::pow(2, 2 + (operand_0_info & 0xF))));

	/* Parse ADDR registers */
	if (instruction.is_mnemonic(UD_Imovspecial))
	{
		instruction.set_mnemonic(UD_Imov);

		if (operand_0_type == FISH_OPERAND_TYPE_REGISTER && context.get_vm_register(operand_0_data) == UD_NONE)
		{
			if (context.register_addr1_id == 0xFFFF)
			{
				context.register_addr1_id = operand_0_data;
				context.set_vm_register(operand_0_data, UD_R_ADDR1);
			}
			else if (context.register_addr2_id == 0xFFFF)
			{
				context.register_addr2_id = operand_0_data;
				context.set_vm_register(operand_0_data, UD_R_ADDR2);
			}
		}
	}

	this->parse_common_operand(instruction, context, 1, operand_1_info, operand_1_data);
	this->parse_common_operand(instruction, context, 0, operand_0_info, operand_0_data);

	instructions.push_back(instruction);
}

void fish_handler::parse_common_operand(ud_instruction& instruction, fish_context& context, std::size_t operand, uint8_t operand_info, uint32_t operand_data)
{
	if (operand_info)
	{
		uint8_t operand_type = static_cast<uint8_t>((operand_info >> 4) & 0xF);
		ud_size operand_size = static_cast<ud_size>(static_cast<uint8_t>(std::pow(2, 2 + (operand_info & 0xF))));
		
		if (operand_type == FISH_OPERAND_TYPE_REGISTER)
		{
			instruction.set_operand_type(operand, UD_OP_REG, operand_size);
			instruction.set_operand_base(operand, context.get_vm_register(operand_data), operand_size);
			
			if (operand_size == UD_SIZE_BYTE && instruction.is_operand_base(operand, UD_NONE))
				instruction.set_operand_base(operand, static_cast<ud_type>(instruction.base_to_size_type(context.get_vm_register(operand_data - 1), operand_size) + (UD_R_AH - UD_R_AL)));
		}
		else if (operand_type == FISH_OPERAND_TYPE_MEMORY)
		{
			instruction.set_operand_type(operand, UD_OP_MEM, operand_size);
			instruction.set_operand_base(operand, context.get_vm_register(operand_data));
		}
		else /* if (operand_type == FISH_OPERAND_TYPE_IMMEDIATE) */
		{
			instruction.set_operand_type(operand, UD_OP_IMM, UD_SIZE_DWORD);
			instruction.set_operand_data(operand, operand_data);
		}

		if (operand_size == UD_SIZE_WORD)
			instruction.pfx_opr = operand_prefix;
	}
}
