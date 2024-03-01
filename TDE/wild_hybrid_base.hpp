#ifndef WILD_HYBRID_BASE_HPP_
#define WILD_HYBRID_BASE_HPP_

#include "wild_base.hpp"

template <class GuestT, class HostT>
class wild_hybrid_base
{
//	static_assert(std::is_base_of<wild_base, GuestT>::value, "GuestT (vm_guest) in class 'wild_hybrid_base' must be derived from class 'wild_base'.");
//	static_assert(std::is_base_of<wild_base, HostT>::value, "HostT (vm_host) in class 'wild_hybrid_base' must be derived from class 'wild_base'.");

public:
	/* ... */

private:
	GuestT vm_guest;	// Inner VM (virtualized by host)
	HostT vm_host;		// Outer VM
};

#endif