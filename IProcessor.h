#pragma once

class IProcessor
{
public:
	/**
	*	@brief register heap entry
	*	@param ustAddress [in] ust entry address
	*	@param size [in] size of heap entry
	*	@param address [in] address of heap entry
	*	@param userSize [in] user requested size for HeapAlloc
	*	@param userAddress [in] address of user data
	*/
	virtual void Register(
		ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress
		) = 0;
};
