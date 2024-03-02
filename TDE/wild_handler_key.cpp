#include "wild_handler_key.hpp"
#include "instruction_emulator.hpp"

#include <idp.hpp>

wild_handler_key::wild_handler_key() :
    id(0),
    index(0),
    mnemonic(UD_Inone),
    operand(0),
    type(UD_NONE),
    size(UD_SIZE_NONE),
    direct_key_parameter(false),
    parameter(0)
{
    // Default condition: always true
    this->condition = [](wild_context const& context, wild_handler_key const& key) -> bool { return true; };
}

bool wild_handler_key::perform(wild_context& context, uint32_t* data)
{
    // Check if the condition is met
    if (this->condition(context, *this))
    {
        if (this->direct_key_parameter)
        {
            if (this->type != UD_OP_REG)
            {
                msg("Direct key parameter type is not OPERAND_TYPE_REGISTER.\n");
                return false;
            }

            // Get source key data
            uint32_t source_key_data = 0;
            if (!context.get_key(this->parameter, &source_key_data))
            {
                msg("Could not get key data from the source key.\n");
                return false;
            }

            // Get destination key data
            uint32_t destination_key_data = 0;
            if (!context.get_key(this->id, &destination_key_data))
            {
                msg("Could not get key data from the destination key.\n");
                return false;
            }

            // Emulate instruction
            instruction::emulate(this->mnemonic, this->size, source_key_data, &destination_key_data);

            // Set destination key data
            if (!context.set_key(this->id, destination_key_data))
            {
                msg("Could not set key data for the destination key.\n");
                return false;
            }
        }
        else
        {
            // Get key data
            uint32_t key_data = 0;
            if (!context.get_key(this->id, &key_data))
            {
                msg("Could not get data from the key.\n");
                return false;
            }

            // Emulate instruction based on the operand type
            if (this->operand > 0)
            {
                // Indirect key
                if (this->type != UD_OP_REG)
                {
                    msg("Indirect key type is not OPERAND_TYPE_REGISTER.\n");
                    return false;
                }
                instruction::emulate(this->mnemonic, this->size, key_data, data);
            }
            else if (this->type == UD_OP_IMM)
            {
                // Immediate value
                instruction::emulate(this->mnemonic, this->size, this->parameter, &key_data);
                // Set key data
                if (!context.set_key(this->id, key_data))
                {
                    msg("Could not set data for the key.\n");
                    return false;
                }
            }
            else
            {
                // Accessor key
                if (this->type != UD_OP_REG)
                {
                    msg("Accessor key type is not OPERAND_TYPE_REGISTER.\n");
                    return false;
                }
                instruction::emulate(this->mnemonic, this->size, *data, &key_data);
                // Set key data
                if (!context.set_key(this->id, key_data))
                {
                    msg("Could not set data for the key.\n");
                    return false;
                }
            }
        }
    }

    return true;
}

bool wild_handler_key::operator<(wild_handler_key const& key) const
{
    return (this->index < key.index);
}
