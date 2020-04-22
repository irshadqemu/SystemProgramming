#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>

//Function Prototypes
//Read PE file,  preform signatures tests, sets the PE-Structures
BOOL ReadAndValidatePE(LPCSTR pcsFilename);
//Allocate memory and Copy Sections
BOOL LoadPESection();
//Fix Relocation
BOOL FixRelocations();
//Fix Import Table
BOOL ResolveImportTable();

BOOL ExecuteTLSCallBacks();

BOOL CallEntryPoint();

