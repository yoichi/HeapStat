#pragma once

#include <set>
#include "IProcessor.h"

class UmdhProcessor : public IProcessor
{
private:
	/**
	*	@brief output file handle
	*/
	HANDLE output_;

	/**
	*	@brief already processed backtrace entries
	*/
	std::set<ULONG64> processed_;

	/**
	*	@brief default constructor (disabled)
	*/
	UmdhProcessor();

public:
	/**
	*	@brief constructor
	*	@param filename [in] output file path
	*	@note opens output file and write header
	*/
	UmdhProcessor(PCSTR filename);

	/**
	*	@brief destractor
	*	@note closes output file
	*/
	~UmdhProcessor();

	/**
	*	@copydoc IProcessor::StartHeap()
	*/
	void StartHeap(ULONG64 heapAddress);

	/**
	*	@copydoc IProcessor::Register()
	*/
	void Register(ULONG64 ustAddress,
		ULONG64 size, ULONG64 address,
		ULONG64 userSize, ULONG64 userAddress);

	/**
	*	@copydoc IProcessor::FinishHeap()
	*/
	void FinishHeap(ULONG64 heapAddress);
};
