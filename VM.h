#ifndef VM_H
#define VM_H

#include <vector>
#include <cstdint>
#include <string>
#include <map>
#include <functional>
#include <thread>
#include <chrono>
#include <windows.h>
#include <mutex>

namespace myobfuscationvm {

// Proprietary instruction set (custom, obfuscated instructions)
enum class Instruction {
    PUSH, POP, ADD, SUB, MUL, DIV, XOR, AND, OR, NOT,
    SHL, SHR, MOV, JMP, JZ, HLT, CUSTOM,
    LOAD, STORE, CALL, RET, PTRACECHK, NOP, HALT
};

// VM Class
class VM {
public:
    void showHelp();
    void showHexDump();
    VM();                                 // Constructor
    ~VM();                                // Destructor

    void init(size_t maxMemorySize = 200 * 1024 * 1024); // Initialize with up to 200 MB memory
    void loadExecutable(const std::string& filename);    // Load an executable file
    void execute();                       // Execute the loaded machine code
    void reset();                         // Reset the VM state for reuse
    void emitDebugInfo();           // Print debug information about the loaded machine code
    void emitExecutionStats();           // Emit profiling stats
    void setHandler(std::string instruction, std::function<void()> handler); // Set custom handler for an instruction

    void startThreadedExecution(); // Start multi-threaded execution of loaded code

    void trackExecutionTime(); // Track execution time for profiling
    void handleCustomInstruction(Instruction instruction); // Handle custom instructions

private:
    std::string filename;              // Name of the loaded executable file
    std::vector<uint8_t> machineCode;     // Stores loaded machine code (up to 200 MB)
    void* execMemory;                     // Pointer to allocated executable memory
    size_t maxMemorySize;                 // Maximum memory size for the VM
    std::map<Instruction, int> instructionCount; // Profiling: instruction execution counts
    std::map<std::string, std::function<void()>> instructionHandlers; // Custom instruction handlers
    std::mutex vmMutex;                   // Mutex for thread synchronization

    void allocateExecMemory(size_t size); // Allocate executable memory
    void releaseExecMemory();             // Release allocated memory

    void executeSingleThread(); // Execute in a single thread
    void executeInThread();    // Wrapper function for multi-threaded execution
    Instruction translateMnemonic(const std::string& mnemonic); // Translate obfuscated mnemonics to instructions
};

} // namespace myobfuscationvm

#endif // VM_H
