#pragma once

class IProcessor
{
public:
	/**
	*	@brief start processing the heap
	*	@param heapAddress [in] heap address
	*/
	virtual void StartHeap(ULONG64 heapAddress) = 0;

	/**
	*	@brief start processing the heap segment
	*	@param start [in] address of HEAP_SEGMENT
	*	@param end [in] HEAP_SEGMENT::LastValidEntry
	*/
	virtual void StartSegment(ULONG64 start, ULONG64 end) = 0;

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

	/**
	*	@brief finish processing the heap segment
	*	@param start [in] address of HEAP_SEGMENT
	*	@param end [in] HEAP_SEGMENT::LastValidEntry
	*/
	virtual void FinishSegment(ULONG64 start, ULONG64 end) = 0;

	/**
	*	@brief finish processing the heap
	*	@param heapAddress [in] heap address
	*/
	virtual void FinishHeap(ULONG64 heapAddress) = 0;
};
