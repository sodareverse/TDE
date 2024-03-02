#ifndef WILD_OPCODE_READER_HPP_
#define WILD_OPCODE_READER_HPP_

#include <cstdint>
#include <type_traits> // For static_assert

class opcode_reader
{
public:
    opcode_reader(uint8_t* opcode_address)
        : opcode_address(opcode_address)
    {

    }

    template <typename T>
    T read(uint32_t offset)
    {
        static_assert(std::is_trivially_copyable<T>::value, "T must be a trivially copyable type");
        if (this->opcode_address != nullptr)
            return *reinterpret_cast<T*>(this->opcode_address + offset);

        return static_cast<T>(0);
    }

private:
    uint8_t* opcode_address;
};

#endif
