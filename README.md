# System Programming Projects
## PELoader
It manually loads the PE executable in memory and executes it. It can also handle relocations and TLS callbacks. It works for both x86 and x64 binaries.
### Key Files:
 [PELoader.cpp](https://github.com/irshadqemu/SystemProgramming/blob/master/PELoader/PELoader/PELoader.cpp): Loader code  
 [HelloWorld.cpp](https://github.com/irshadqemu/SystemProgramming/blob/master/PELoader/HelloWorld/HelloWorld.cpp): Test program that loader will execute.
 
 ## MyImportResolution
 A custom implementation of WIN API GetProcAddress. It can handle resolution by names and resolution by oridinal. It can also handle forwarded exports. 
### Key Files:
[MyImportResolution.cpp](https://github.com/irshadqemu/SystemProgramming/blob/master/MyImportResolution/MyImportResolution/MyImportResolution.cpp): implementation of GetProcAddress.  
[Test.cpp](https://github.com/irshadqemu/SystemProgramming/blob/master/MyImportResolution/Test/Test.cpp): A test program to verify the results.  
