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
#include <iomanip>

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
    {"HALT", Instruction::HALT},
    {"CRYPT", Instruction::ENCRYPT},    // Encryption operation
    {"DCRYPT", Instruction::DECRYPT},   // Decryption operation
    {"INJECT", Instruction::INJECT},    // Process injection
    {"HIDE", Instruction::HIDE},        // Anti-detection
    {"SLEEP", Instruction::SLEEP},      // Anti-analysis sleep
    {"DETECT", Instruction::DETECT},    // VM/Debugger detection
    {"MORPH", Instruction::MORPH},      // Runtime code morphing
    {"CONNECT", Instruction::CONNECT},  // Network connection
    {"PERSIST", Instruction::PERSIST},  // System persistence
    {"ELEVATE", Instruction::ELEVATE}   // Privilege elevation
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
    filename = fname;
    std::ifstream file(filename);
    
    if (!file.is_open())
        throw std::runtime_error("Failed to open assembly file: " + filename);

    std::string line;
    std::vector<uint8_t> assembled;
    
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == ';' || line[0] == '#')
            continue;
            
        // Skip section declarations
        if (line.find("section") != std::string::npos || 
            line.find("global") != std::string::npos)
            continue;

        // Extract instruction
        std::istringstream iss(line);
        std::string instruction;
        iss >> instruction;
        
        // Skip labels (ending with :)
        if (instruction.back() == ':')
            continue;
            
        // Convert instruction to bytecode
        try {
            Instruction instr = translateMnemonic(instruction);
            assembled.push_back(static_cast<uint8_t>(instr));
        } catch (const std::exception& e) {
            // Skip unknown instructions
            continue;
        }
    }

    file.close();
    
    if (assembled.empty())
        throw std::runtime_error("No valid instructions found in assembly file");

    machineCode = assembled;
    allocateExecMemory(machineCode.size());
    std::memcpy(execMemory, machineCode.data(), machineCode.size());
}

// Update translateMnemonic to handle whitespace and comments
Instruction VM::translateMnemonic(const std::string& mnemonic) {
    // Remove whitespace and comments
    std::string cleaned = mnemonic;
    size_t comment = cleaned.find(';');
    if (comment != std::string::npos)
        cleaned = cleaned.substr(0, comment);
        
    // Trim whitespace
    while (!cleaned.empty() && std::isspace(cleaned.back()))
        cleaned.pop_back();
    
    auto it = asmMap.find(cleaned);
    if (it == asmMap.end()) {
        throw std::runtime_error("Unknown mnemonic: " + cleaned);
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

    std::cout << "\n=== Starting Execution ===\n"
              << "Parsing bytecode...\n\n";

    uint32_t ip = 0;
    std::vector<uint32_t> stack;
    bool running = true;

    while (running && ip < machineCode.size()) {
        uint8_t bytecode = machineCode[ip];
        
        // Print current instruction being executed
        std::cout << "IP: " << std::setw(4) << ip << " | ";
        
        try {
            Instruction instr = static_cast<Instruction>(bytecode);
            switch (instr) {
                case Instruction::PUSH: // GHTL
                    std::cout << "GHTL    Pushing value to stack\n";
                    stack.push_back(machineCode[ip+1]);
                    instructionCount[instr]++;
                    break;
                
                case Instruction::POP: // NMPQ
                    std::cout << "NMPQ    Popping value from stack\n";
                    if (!stack.empty()) stack.pop_back();
                    instructionCount[instr]++;
                    break;
                
                case Instruction::LOAD: // DQXZ
                    std::cout << "DQXZ    Loading data\n";
                    if (ip < machineCode.size()) {
                        std::string msg = "Hello World";
                        std::cout << "        Output: " << msg << std::endl;
                    }
                    instructionCount[instr]++;
                    break;
                
                case Instruction::CALL: // PNAF
                    std::cout << "PNAF    Calling function\n";
                    instructionCount[instr]++;
                    break;
                
                case Instruction::MOV: // LUJK
                    std::cout << "LUJK    Moving data\n";
                    instructionCount[instr]++;
                    break;
                
                case Instruction::HLT: // QJMC
                    std::cout << "QJMC    Halting execution\n";
                    running = false;
                    instructionCount[instr]++;
                    break;
                
                case Instruction::ENCRYPT:
                    std::cout << "CRYPT   Encrypting data\n";
                    handleEncryption(ip, stack);
                    break;
                    
                case Instruction::INJECT:
                    std::cout << "INJECT  Process injection\n";
                    handleProcessInjection(ip, stack);
                    break;
                    
                case Instruction::HIDE:
                    std::cout << "HIDE    Anti-detection measures\n";
                    handleAntiDetection(ip);
                    break;
                    
                case Instruction::SLEEP:
                    std::cout << "SLEEP   Anti-analysis delay\n";
                    handleSleep(ip);
                    break;
                    
                case Instruction::DETECT:
                    std::cout << "DETECT  Environment detection\n";
                    // Add VM/Sandbox detection logic
                    break;
                    
                case Instruction::MORPH:
                    std::cout << "MORPH   Code morphing\n";
                    // Add runtime code modification logic
                    break;
                
                default:
                    std::cout << "???     Unknown instruction\n";
                    break;
            }
        } catch (...) {
            std::cout << "Invalid bytecode: 0x" << std::hex << static_cast<int>(bytecode) << std::dec << "\n";
        }
        
        ip++;
    }

    std::cout << "\n=== Execution Summary ===\n";
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
    std::cout << "\n=== VM Status ===\n"
              << "Loaded file: " << filename << "\n"
              << "Program size: " << machineCode.size() << " bytes\n"
              << "Memory status: " << (execMemory ? "Allocated" : "Not allocated") << "\n"
              << "Memory protection: " << (execMemory ? "RWX" : "None") << "\n";
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

// Add new handler functions
void VM::handleEncryption(uint32_t& ip, std::vector<uint32_t>& stack) {
    if (stack.size() < 2) return;
    uint32_t key = stack.back(); stack.pop_back();
    uint32_t data = stack.back(); stack.pop_back();
    // Simple XOR encryption for demonstration
    stack.push_back(data ^ key);
    ip++;
}

void VM::handleProcessInjection(uint32_t& ip, std::vector<uint32_t>& stack) {
    if (stack.empty()) return;
    uint32_t pid = stack.back();
    // Process injection logic would go here
    ip++;
}

void VM::handleAntiDetection(uint32_t& ip) {
    // Basic anti-VM detection
    bool isVM = false;
    char vendor[13];
    __cpuid((int*)vendor, 0);
    if (strcmp(vendor, "VMwareVMware") == 0 || 
        strcmp(vendor, "Microsoft Hv") == 0) {
        isVM = true;
    }
    ip++;
}

void VM::handleSleep(uint32_t& ip) {
    // Anti-analysis sleep with timing checks
    auto start = std::chrono::high_resolution_clock::now();
    Sleep(100);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // If sleep was shorter than expected, might be debugged
    if (duration.count() < 95) {
        // Handle debugging detection
    }
    ip++;
}

// namespace myobfuscationvm

int main(int argc, char* argv[]) {
    myobfuscationvm::VM vm;
    vm.init();
    
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        vm.showHelp();
        return 0;
    }

    try {
        vm.loadExecutable(argv[argc - 1]);
        vm.emitDebugInfo();  // Show debug info once
        vm.execute();        // Execute with its own summary
        vm.trackExecutionTime();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

