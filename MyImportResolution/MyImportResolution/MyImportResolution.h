// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the MYIMPORTRESOLUTION_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// MYIMPORTRESOLUTION_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MYIMPORTRESOLUTION_EXPORTS
#define MYIMPORTRESOLUTION_API __declspec(dllexport)
#else
#define MYIMPORTRESOLUTION_API __declspec(dllimport)
#endif
#include <Windows.h>


extern MYIMPORTRESOLUTION_API FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
extern MYIMPORTRESOLUTION_API HMODULE MyLoadLibraryA(LPCSTR lpLibFileName);

MYIMPORTRESOLUTION_API FARPROC MyGetProcAddress(HMODULE hModule,LPCSTR  lpProcName);
MYIMPORTRESOLUTION_API HMODULE MyLoadLibraryA( LPCSTR lpLibFileName);