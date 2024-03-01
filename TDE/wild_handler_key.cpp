#include "wild_handler_key.hpp"
#include "instruction_emulator.hpp"

#include <idp.hpp>

wild_handler_key::wild_handler_key()
{
	this->id = 0;
	this->index = 0;

	this->mnemonic = UD_Inone;
	this->operand = 0;

	this->type = UD_NONE;
	this->size = UD_SIZE_NONE;

	this->direct_key_parameter = false;
	this->parameter = 0;

	this->condition = [](wild_context const& context, wild_handler_key const& key) -> bool { return true; };
}

bool wild_handler_key::perform(wild_context& context, uint32_t* data)
{
	if (this->condition(context, *this))
	{
		if (this->direct_key_parameter)
		{
			if (this->type != UD_OP_REG)
			{
				msg("[CodeDevirtualizer] Direct key param type != OPERAND_TYPE_REGISTER.\n");
				return false;
			}

			uint32_t source_key_data = 0;

			if (!context.get_key(this->parameter, &source_key_data))
			{
				msg("[CodeDevirtualizer] Could not get key data from source key.\n");
				return false;
			}

			uint32_t destination_key_data = 0;

			if (!context.get_key(this->id, &destination_key_data))
			{
				msg("[CodeDevirtualizer] Could not get key data from destination key.\n");
				return false;
			}

			instruction::emulate(this->mnemonic, this->size, source_key_data, &destination_key_data);

			if (!context.set_key(this->id, destination_key_data))
			{
				msg("[CodeDevirtualizer] Could not set key data for destination key.\n");
				return false;
			}
		}
		else if (this->operand > 0)
		{
			if (this->type != UD_OP_REG)
			{
				msg("[CodeDevirtualizer] Indirect key type != OPERAND_TYPE_REGISTER.\n");
				return false;
			}

			uint32_t key_data = 0;

			if (!context.get_key(this->id, &key_data))
			{
				msg("[CodeDevirtualizer] Could not get data from key.\n");
				return false;
			}

			instruction::emulate(this->mnemonic, this->size, key_data, data);
		}
		else if (this->type == UD_OP_IMM)
		{
			uint32_t key_data = 0;

			if (!context.get_key(this->id, &key_data))
			{
				msg("[CodeDevirtualizer] Could not get data from key.\n");
				return false;
			}

			instruction::emulate(this->mnemonic, this->size, this->parameter, &key_data);

			if (!context.set_key(this->id, key_data))
			{
				msg("[CodeDevirtualizer] Could not set data for key.\n");
				return false;
			}
		}
		else
		{
			if (this->type != UD_OP_REG)
			{
				msg("[CodeDevirtualizer] Accessor key type != OPERAND_TYPE_REGISTER.\n");
				return false;
			}

			uint32_t key_data = 0;

			if (!context.get_key(this->id, &key_data))
			{
				msg("[CodeDevirtualizer] Could not get data from key.\n");
				return false;
			}
			
			instruction::emulate(this->mnemonic, this->size, *data, &key_data);

			if (!context.set_key(this->id, key_data))
			{
				msg("[CodeDevirtualizer] Could not set data for key.\n");
				return false;
			}
		}
	}

	return true;
}

bool wild_handler_key::operator<(wild_handler_key const& key) const
{
    return (this->index < key.index);
}