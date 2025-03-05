// NetHookInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

int main()
{
    std::cout << "Hello World!\n";


    // look for all halo processes

    // preload dll so we can get the addresses for stuff
    // specifically the event log thing

    // check to see if dll is already injected
    // if it is, then skip straight to the looping

    // hook in dll to the target process
    // let the dll do its stuff

    // then just run a loop within this tool to read the injected dlls event log\

    // readmem on the eventlog address to get the ptr and whatever
}
