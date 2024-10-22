// ReflectiveDLLLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "Imports.h"



/* functionality same as localDLL except dll pulled remotely
based off https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
*/
void localReflecty() {/* functionality same as localDLL except dll pulled remotely
based off https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
*/
}


void remoteDLL(IN HANDLE hProc) {

	
}

void localDLL() {
	cout << "current PID: " << GetCurrentProcessId() << endl;

	if (LoadLibraryA("C:\\Users\\ashev\\source\\repos\\ReflectiveDLLLoader\\x64\\Debug\\injectDLL.dll") == NULL) {
		cout << "failed: " << GetLastError() << endl; 
	}
	cout << "kill me"; 
	auto dum = getchar(); 

}

int main()
{
	/* create injecty process */
	//STARTUPINFOA si{};
	//PROCESS_INFORMATION pi{};

	//CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	//remoteDLL(pi.hProcess); 

	////cleanup 
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);
	//PEParserMonster();
	PELoader(); 
}
