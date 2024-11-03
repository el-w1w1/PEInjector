# PE Injector
Project to explore Windows Portable Executables with the goal of having a Local PE Injector that can pull exe's and dlls over the network and inject them locally. 

Currently have a working parser that is able to parse the base relocation table and rewrite static addresses with the correct value. 

Inspiration/Learning from: 
- https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
- https://0xrick.github.io/win-internals/pe1/
- maldevacademy -> Local PE Injection
