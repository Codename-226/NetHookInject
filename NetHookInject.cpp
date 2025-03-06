// NetHookInject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <fstream>

#include <vector>
using namespace std;

const char* MCC_PROC_STR = "mcc-win64-shipping.exe";
const char* INJECTED_MODULE_NAME = "NetHook.dll";
const char* INJECTED_MODULE_PATH = "D:\\Projects\\VS\\NetHookInject\\x64\\Release\\NetHook.dll";

// TODO: share the declaration between the two projects (so its only written in one place)
const int page_size = 0xffff; // NOTE: should be large enough to fit the largest possible log entry (probably 128 bytes?)
class LogData {
public:
    char* buffer = 0;
    int pages_allocated = 1;
    int used = 0;
};

HANDLE find_process(const char* target_process, HMODULE* previous_injection) {

    DWORD proc_id_array[1024], cbNeeded;
    if (!EnumProcesses(proc_id_array, sizeof(proc_id_array), &cbNeeded)) {
        cout << "[INIT] couldn't find target process: failed to enumerate.\n";
        return 0;}

    HANDLE process_id;
    DWORD processes_count = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < processes_count; i++) {
        if (!proc_id_array[i]) continue;

        //process_id = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, proc_id_array[i]);
        process_id = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id_array[i]);
        if (!process_id) continue;

        HMODULE modules_array[256];
        DWORD mods_buffersize_used;
        if (EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {

            // if current process matches target process by name
            char process_name[MAX_PATH];
            GetModuleBaseNameA(process_id, modules_array[0], process_name, sizeof(process_name));
            if (strcmp(process_name, target_process)) continue;

            // iterate through the rest of the modules to see if ours is already injected
            int modules_count = mods_buffersize_used / sizeof(HMODULE);
            for (int j = 1; j < modules_count; j++) {
                GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
                if (!strcmp(process_name, INJECTED_MODULE_NAME))
                    *previous_injection = modules_array[j];
            }
            return process_id;
        }

        CloseHandle(process_id);
    }
    return 0;
}

HMODULE inject_dll(HANDLE process_id, const char* dll_path, const char* dll_name) {

    LPVOID path_str_ptr = VirtualAllocEx(process_id, 0, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!path_str_ptr) {
        cout << "[INIT] could not allocate path string memory.\n";
        return 0;}

    if (!WriteProcessMemory(process_id, path_str_ptr, dll_path, strlen(dll_path) + 1, NULL)) {
        cout << "[INIT] could not write to path string memory.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    HANDLE hThread = CreateRemoteThread(process_id, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), path_str_ptr, 0, NULL);
    if (!hThread) {
        cout << "[INIT] could not create remote thread.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // then we get the module 
    HMODULE modules_array[256];
    DWORD mods_buffersize_used;
    if (!EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {
        cout << "[INIT] could not iterate modules.\n";
        return 0;}

    // if current process matches target process by name
    char process_name[MAX_PATH];
    // iterate through modules to find matching
    int modules_count = mods_buffersize_used / sizeof(HMODULE);

    HMODULE hooked_dll = 0; // invalid pointer becuase its memory belongs to the other process
    for (int j = 1; j < modules_count; j++) {
        GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
        if (!strcmp(process_name, dll_name))
            hooked_dll = modules_array[j];
    }
    if (!hooked_dll) {
        cout << "[INIT] could not find our module via iteration.\n";
        return 0;}

    return hooked_dll;
}


INT64 GetLogsOffset() {
    // preload dll so we can get the addresses for stuff
    // specifically the event log thing
    if (!SetEnvironmentVariableA("DLL_DO_NOT_INIT", "OK")) {
        cout << "[INIT] couldn't define DLL DO NOT INIT\n";
        return -1;}

    // load a copy of the module to this process so we can map offsets
    HMODULE query_module = LoadLibraryA(INJECTED_MODULE_PATH);
    if (!query_module) {
        std::cerr << "[INIT] couldn't load injected dll from file path.\n";
        return -1;}

    // get offset of globals struct
    typedef void* (__stdcall* GetLogDataPtr)();
    GetLogDataPtr logs_func = (GetLogDataPtr)GetProcAddress(query_module, "GetLogDataPtr");
    if (!logs_func) {
        std::cerr << "[INIT] couldn't find address of get logs function.\n";
        return -1;}

    // convert address found in query module to offset, then apply that offset to the external module
    INT64 test1 = ((INT64)(logs_func()) - (INT64)query_module);

    // release query module
    if (!FreeLibrary(query_module)) {
        std::cerr << "[INIT] failed to release query module.\n";
        return -1;}

    return test1;
}


int main(){
    std::cout << "[INIT] Hello World!\n";

    HMODULE previous_injection = 0;
    HANDLE proc_id = find_process(MCC_PROC_STR, &previous_injection);
    if (!proc_id) {
        cout << "[INIT] could not find process.\n";
        return -1;}



    // check to see if dll is already injected
    // if it is, then skip straight to the looping
    if (!previous_injection) {

        // hook in dll to the target process
        // let the dll do its stuff
        previous_injection = inject_dll(proc_id, INJECTED_MODULE_PATH, INJECTED_MODULE_NAME);
        if (!previous_injection) {
            cout << "[INIT] dll injection failed.\n"; 
            return -1;

    }} else cout << "[INIT] dll already injected, connecting to that instead.\n";

    // NOTE: we can eventually harcode the offset once we've finalized the executable
    // however, the injector will be finished long before the injected dll will be, so we'll leave it as is
    INT64 log_struct_offset = GetLogsOffset();


    void* external_log_ptr = (void*)((UINT64)previous_injection + log_struct_offset);
    





    // then just run a loop within this tool to read the injected dlls event log\
    // readmem on the eventlog address to get the ptr and whatever
    cout << "[INIT] running read loop\n";
    cout << hex;

    int current_read_position = 0;
    int temp = 0;
    LogData debug_values = {0};
    char log_output_buffer[1024];


    while (true) {
        Sleep(500);
        if (!ReadProcessMemory(proc_id, external_log_ptr, &debug_values, sizeof(LogData), 0))
            goto read_log_error;


        if (current_read_position >= debug_values.used)
            goto buffer_up_to_date;

        if (!debug_values.buffer)
            goto null_buffer_error;
        
        // cap read size to 1024
        temp = debug_values.used - current_read_position;
        if (temp >= sizeof(log_output_buffer)) temp = sizeof(log_output_buffer) - 1;

        if (!ReadProcessMemory(proc_id, debug_values.buffer + current_read_position, log_output_buffer, temp, 0))
            goto read_buffer_error;
        log_output_buffer[temp] = '\0';

        current_read_position = debug_values.used;
        cout << log_output_buffer;
        continue;

    read_log_error:
        cout << "[LOOP] failed to read logs struct.\n";
        continue;
    null_buffer_error:
        cout << "[LOOP] logs buffer is null.\n";
        continue;
    read_buffer_error:
        cout << "[LOOP] failed to read logs str buffer.\n";
        continue;
    buffer_up_to_date:
        cout << "[LOOP] nothing to report. buffer ptr: " << (uint64_t)debug_values.buffer << " pages allocated: " << debug_values.pages_allocated << " bytes used: " << debug_values.used << endl;
        continue;
    }
}
