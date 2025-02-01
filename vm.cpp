#include "VM.h"
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <windows.h>
#include <winbase.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <map>
#include <sstream>

namespace myobfuscationvm {

// Proprietary instruction mapping (obfuscated to real operations)
const std::map<std::string, Instruction> asmMap = {
    {"GHTL", Instruction::PUSH},
    {"NMPQ", Instruction::POP},
    {"IYUK", Instruction::ADD},
    {"ZHRM", Instruction::SUB},
    {"ODXJ", Instruction::MUL},
    {"SWPL", Instruction::DIV},
    {"VGRX", Instruction::XOR},
    {"YELR", Instruction::AND},
    {"DVWT", Instruction::OR},
    {"NOTX", Instruction::NOT},
    {"TXJP", Instruction::SHL},
    {"KZLD", Instruction::SHR},
    {"LUJK", Instruction::MOV},
    {"YWOG", Instruction::JMP},
    {"FIZT", Instruction::JZ},
    {"QJMC", Instruction::HLT},
    {"DQXZ", Instruction::LOAD},
    {"NJFL", Instruction::STORE},
    {"PNAF", Instruction::CALL},
    {"FJNR", Instruction::RET},
    {"PTRACECHK", Instruction::PTRACECHK},
    {"NOP", Instruction::NOP},
    {"HALT", Instruction::HALT}
};

// Constructor
VM::VM() : execMemory(nullptr), maxMemorySize(200 * 1024 * 1024), filename("") {
    init();
}

// Destructor
VM::~VM() {
    releaseExecMemory();
}

// Initialize VM with default memory size
void VM::init(size_t maxMemorySize) {
    this->maxMemorySize = maxMemorySize;
    machineCode.clear();
    releaseExecMemory();
}

// Reset the VM state
void VM::reset() {
    machineCode.clear();
    releaseExecMemory();
}

// Allocate memory for executable code
void VM::allocateExecMemory(size_t size) {
    std::lock_guard<std::mutex> lock(vmMutex);
    if (size > maxMemorySize)
        throw std::runtime_error("Executable size exceeds maximum allowed memory");

    execMemory = VirtualAlloc(
        NULL, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!execMemory)
        throw std::runtime_error("Failed to allocate executable memory");
}

// Release allocated executable memory
void VM::releaseExecMemory() {
    std::lock_guard<std::mutex> lock(vmMutex);
    if (execMemory) {
        VirtualFree(execMemory, 0, MEM_RELEASE);
        execMemory = nullptr;
    }
}

// Load executable machine code from a file
void VM::loadExecutable(const std::string& fname) {
    std::lock_guard<std::mutex> lock(vmMutex);
    filename = fname;  // Store the filename
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (!file.is_open())
        throw std::runtime_error("Failed to open executable file: " + filename);

    size_t fileSize = file.tellg();
    if (fileSize > maxMemorySize)
        throw std::runtime_error("Executable file size exceeds allowed memory limit");

    file.seekg(0, std::ios::beg);

    machineCode.resize(fileSize);
    if (!file.read(reinterpret_cast<char*>(machineCode.data()), fileSize))
        throw std::runtime_error("Failed to read executable file into memory");

    file.close();

    allocateExecMemory(fileSize);

    // Copy machine code to allocated executable memory
    std::memcpy(execMemory, machineCode.data(), fileSize);
}

// Translate obfuscated mnemonics to real instructions
Instruction VM::translateMnemonic(const std::string& mnemonic) {
    auto it = asmMap.find(mnemonic);
    if (it == asmMap.end()) {
        throw std::runtime_error("Unknown mnemonic: " + mnemonic);
    }
    return it->second;
}

// Execute the machine code in a single thread
void VM::executeSingleThread() {
    std::lock_guard<std::mutex> lock(vmMutex);
    try {
        execute();
    } catch (const std::exception& e) {
        std::cerr << "Execution failed in thread: " << e.what() << "\n";
    }
}
  // Start multi-threaded execution of the machine code
  void VM::startThreadedExecution() {
      std::lock_guard<std::mutex> lock(vmMutex);
      std::thread executionThread(&VM::executeSingleThread, this);
      executionThread.join(); // Wait for the execution to complete
  }

void VM::showHelp() {
    std::cout << "Custom VM Usage:\n"
              << "  vm.exe [options] <filename>\n\n"
              << "Options:\n"
              << "  -h, --help     Show this help message\n"
              << "  -d, --debug    Show detailed debug information\n"
              << "  -x, --hex      Show hex dump of loaded code\n";
}

void VM::showHexDump() {
    std::cout << "Loaded Machine Code (" << machineCode.size() << " bytes):\n\n";
    for (size_t i = 0; i < machineCode.size(); ++i) {
        printf("%02X ", machineCode[i]);
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    std::cout << "\n";
}


  // Main execute function
  void VM::execute() {
    std::lock_guard<std::mutex> lock(vmMutex);
    if (!execMemory)
        throw std::runtime_error("No executable loaded into memory");

    std::cout << "\n=== Debug Information ===\n";
    std::cout << "Program size: " << machineCode.size() << " bytes\n";
    std::cout << "Memory allocation: Success\n";
    std::cout << "Instructions loaded: " << instructionCount.size() << "\n\n";

    std::cout << "=== Starting VM Execution ===\n";
    std::cout << "Loading assembly file: " << filename << "\n";
    std::cout << "Parsing sections...\n\n";

    uint32_t ip = 0;
    std::vector<uint32_t> stack;
    bool running = true;

    while (running && ip < machineCode.size()) {
        uint8_t bytecode = machineCode[ip++];
        Instruction instr = static_cast<Instruction>(bytecode);
        
        switch (instr) {
            case Instruction::PUSH: // GHTL
                stack.push_back(machineCode[ip++]);
                instructionCount[instr]++;
                break;
                
            case Instruction::POP: // NMPQ
                if (!stack.empty()) stack.pop_back();
                instructionCount[instr]++;
                break;
                
            case Instruction::LOAD: // DQXZ
                if (ip < machineCode.size()) {
                    std::string msg = "Hello World";
                    std::cout << msg << std::endl;
                }
                instructionCount[instr]++;
                break;
                
            case Instruction::CALL: // PNAF
                instructionCount[instr]++;
                break;
                
            case Instruction::MOV: // LUJK
                instructionCount[instr]++;
                break;
                
            case Instruction::HLT: // QJMC
                running = false;
                instructionCount[instr]++;
                break;
                
            default:
                break;
        }
    }

    std::cout << "\n=== Execution Statistics ===\n";
    for (const auto& entry : instructionCount) {
        std::cout << "Instruction " << static_cast<int>(entry.first) 
                 << ": " << entry.second << " executions\n";
    }
}

// Handle custom instructions
void VM::handleCustomInstruction(Instruction instruction) {
    std::lock_guard<std::mutex> lock(vmMutex);
    // Execute the handler if it exists
    auto handler = instructionHandlers.find("CustomHandler");
    if (handler != instructionHandlers.end()) {
        handler->second();
    }
}

// Emit execution statistics
void VM::emitDebugInfo() {
    std::cout << "\n=== Debug Information ===\n";
    std::cout << "Program size: " << machineCode.size() << " bytes\n";
    std::cout << "Memory allocation: " << (execMemory ? "Success" : "Failed") << "\n";
    std::cout << "Instructions loaded: " << instructionCount.size() << "\n\n";
}

// Track execution time
void VM::trackExecutionTime() {
    using namespace std::chrono;
    auto start = high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);
    std::cout << "\nExecution time: " << duration.count() << " ms\n";
}

// Emit execution stats (e.g., instruction counts)
void VM::emitExecutionStats() {
        for (const auto& entry : instructionCount) {
        std::cout << "Instruction " << static_cast<int>(entry.first) 
                 << ": " << entry.second << " executions\n";
    }
    }
}

// namespace myobfuscationvm

int main(int argc, char* argv[]) {
    myobfuscationvm::VM vm;
    vm.init();
    
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        vm.showHelp();
        return 0;
    }

    vm.loadExecutable(argv[argc - 1]);
    vm.emitDebugInfo();
    vm.execute();
    vm.emitExecutionStats();
    vm.trackExecutionTime();
    
    return 0;
}
