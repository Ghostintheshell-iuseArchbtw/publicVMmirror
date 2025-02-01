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
#include <random>
#include <algorithm>

namespace myobfuscationvm {

// Forward declarations
class VM;

// Proprietary instruction set
enum class Instruction {
    PUSH, POP, ADD, SUB, MUL, DIV, XOR, AND, OR, NOT,
    SHL, SHR, MOV, JMP, JZ, HLT, CUSTOM,
    LOAD, STORE, CALL, RET, PTRACECHK, NOP, HALT,
    
    // Advanced protection instructions
    ENCRYPT,    // Encryption operation
    DECRYPT,    // Decryption operation
    INJECT,     // Process injection
    HIDE,       // Anti-detection
    SLEEP,      // Anti-analysis sleep
    DETECT,     // VM/Debugger detection
    MORPH,      // Runtime code morphing
    CONNECT,    // Network connection
    PERSIST,    // System persistence
    ELEVATE     // Privilege elevation
};

// Support structures - moved before VM class
struct CodeBlock {
    std::vector<uint8_t> code;
    bool encrypted;
    uint32_t originalSize;
    uint32_t morphCount;
};

struct MorphRule {
    std::vector<Instruction> pattern;
    std::vector<Instruction> replacement;
    float probability;
};

struct MemoryBlock {
    void* ptr;
    size_t size;
    bool executable;
};

// VM Class
class VM {
public:
    VM();                                 // Constructor
    ~VM();                                // Destructor

    void init(size_t maxMemorySize = 200 * 1024 * 1024); // Initialize with up to 200 MB memory
    void loadExecutable(const std::string& filename);    // Load an executable file
    void execute();                       // Execute the loaded machine code
    void reset();                         // Reset the VM state for reuse
    void emitDebugInfo();                // Print debug information

    void loadLibrary(const std::string& dllPath); // Load external DLL
    void setHandler(std::string instruction, std::function<void()> handler); // Set custom handler

    void startThreadedExecution(); // Start multi-threaded execution
    void trackExecutionTime();     // Track execution time
    void emitExecutionStats();     // Emit profiling stats

    void handleCustomInstruction(Instruction instruction); // Handle custom instructions
    void showHelp();              // Show help message
    void showHexDump();           // Show hex dump of code

private:
    std::vector<uint8_t> machineCode;     // Machine code storage
    void* execMemory;                     // Executable memory pointer
    size_t maxMemorySize;                 // Maximum memory size
    std::map<Instruction, int> instructionCount; // Instruction counts
    std::map<std::string, std::function<void()>> instructionHandlers; // Custom handlers
    std::mutex vmMutex;                   // Thread synchronization
    std::string filename;                 // Current file name
    std::mt19937 rng;                     // Random number generator

    // Core VM operations
    void allocateExecMemory(size_t size);
    void releaseExecMemory();
    void executeSingleThread();
    void executeInThread();
    Instruction translateMnemonic(const std::string& mnemonic);

    // Protection handlers
    void handleEncryption(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleProcessInjection(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleAntiDetection(uint32_t& ip);
    void handleSleep(uint32_t& ip);
    void handleMorphing(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleShuffle(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleTrap(uint32_t& ip);
    void handleOpaquePredicate(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleJumpTable(uint32_t& ip, std::vector<uint32_t>& stack);
    void handleDebugCheck(uint32_t& ip);

    // Metamorphic engine methods
    void applyMorphingRules(CodeBlock& block);
    void applyRule(CodeBlock& block, const MorphRule& rule);
    void shuffleBlock(std::vector<uint8_t>& block);
    uint32_t generateRandom();
};

} // namespace myobfuscationvm

#endif // VM_H
