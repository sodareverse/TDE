#ifndef WILD_CONTEXT_KEYS_HPP_
#define WILD_CONTEXT_KEYS_HPP_

#include <stdint.h>
#include <vector>

class wild_context_keys
{
public:
	void reset_keys();
	void reset_key_data();

	void add_key(uint32_t offset);

	bool set_key(uint32_t offset, uint32_t data);
	bool get_key(uint32_t offset, uint32_t* data) const;

	uint32_t get_key_offset(uint8_t index) const;
	uint32_t get_key_data(uint8_t index) const;

private:
	/* <T1 = context_offset, T2 = key_data> */
	std::vector<std::pair<uint32_t, uint32_t>> keys;
};

#endif