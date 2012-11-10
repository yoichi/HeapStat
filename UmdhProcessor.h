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
	*	@brief target is x64 or not
	*/
	const bool isTarget64_;

	/**
	*	@brief gflag
	*/
	const ULONG32 ntGlobalFlag_;

	/**
	*	@brief already processed backtrace entries
	*/
	std::set<ULONG64> processed_;

	/**
	*	@brief operator (disabled)
	*	@note to avoid C4512 warning
	*/
	UmdhProcessor& operator=(const UmdhProcessor&);

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
