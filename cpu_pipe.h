#ifndef CPUPIPE_H
#define CPUPIPE_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <cstdint>
#include <optional>
#include <iostream>
#include <sstream>


const uint64_t MASK64 = 0xFFFFFFFFFFFFFFFFULL;
const uint64_t MAX_ADDRESS = 0x7FFFFFFFFFFFFFFFULL;

struct Instruction {
    std::string opcode;
    std::vector<std::string> args;
    uint64_t address;
    int line;
    std::string source;
};

struct ProgramParseResult {
    std::vector<Instruction> instructions;
    std::map<std::string, uint64_t> labels;
    std::map<uint64_t, uint8_t> memory;
};

struct ConditionCodes {
    bool ZF = true;
    bool SF = false;
    bool OF = false;
};

// pipeline register
struct F_Register {
    uint64_t predPC = 0;

    bool stall = false;
    bool bubble = false;
};
 // stat 1 OK, 2 HLT, 3 ADR, 4 INS
struct D_Register {
    int stat = 1;
    int icode = 1; // nop
    int ifun = 0;
    int rA = 15; // no reg
    int rB = 15;
    uint64_t valC = 0;
    uint64_t valP = 0;
    uint64_t PC = 0;
    
    bool stall = false;
    bool bubble = false;
};

struct E_Register {
    int stat = 1;
    int icode = 1;
    int ifun = 0;
    uint64_t valC = 0;
    uint64_t valA = 0;
    uint64_t valB = 0;
    uint64_t valP = 0;
    uint64_t PC = 0;
    int dstE = 15;
    int dstM = 15;
    int srcA = 15;
    int srcB = 15;
    
    bool stall = false;
    bool bubble = false;
};

struct M_Register {
    int stat = 1;
    int icode = 1;
    bool Cnd = false;
    uint64_t valE = 0;
    uint64_t valA = 0;
    uint64_t valP = 0;
    uint64_t PC = 0;
    int dstE = 15;
    int dstM = 15;
    
    bool stall = false;
    bool bubble = false;
};

struct W_Register {
    int stat = 1;
    int icode = 1;
    uint64_t valE = 0;
    uint64_t valM = 0;
    uint64_t valP = 0;
    uint64_t PC = 0;
    int dstE = 15;
    int dstM = 15;
    
    bool stall = false;
    bool bubble = false;
};

class Y86CPU {
public:
    Y86CPU(const std::vector<Instruction>& program,
           const std::map<std::string, uint64_t>& labels,
           const std::map<std::string, uint64_t>& initial_regs,
           const std::map<uint64_t, uint8_t>& initial_mem,
           const std::map<std::string, int>& initial_flags,
           uint64_t initial_pc);

    std::string run();

private:
    std::vector<Instruction> program;
    std::map<std::string, uint64_t> labels;
    std::map<uint64_t, int> addr_to_index;
    
    std::map<std::string, uint64_t> registers;
    ConditionCodes flags;
    std::map<uint64_t, uint8_t> memory;
    
    int pc_index; // PC
    
    std::string stat;
    std::string last_error;


    F_Register F;
    D_Register D;
    E_Register E;
    M_Register M;
    W_Register W;

    // next state reg
    uint64_t f_predPC; 
    D_Register D_in;
    E_Register E_in;
    M_Register M_in;
    W_Register W_in;

    void step();
    std::string snapshot();
    
    // pipeline stage
    void fetch();
    void decode();
    void execute();
    void memory1();
    void writeback();
    void update_pipereg();

    uint64_t get_reg_val(int reg_id);
    void set_reg_val(int reg_id, uint64_t val);
    std::string reg_name(int id);
    int reg_id(const std::string& name);
    
    uint64_t get_reg_val(const std::string& reg);
    void set_reg_val(const std::string& reg, uint64_t val);

    uint64_t read_qword(uint64_t addr);
    void write_qword(uint64_t addr, uint64_t val);
    void write_byte(uint64_t addr, uint8_t val);
    
    uint64_t resolve_immediate(const std::string& token);
    std::pair<uint64_t, std::string> decode_memory(const std::string& operand);
    
    void error(const std::string& stat, const std::string& msg);
    int address_to_index(uint64_t addr);
    uint64_t current_address();
};

// Parsing functions (AIgened)
ProgramParseResult parse_yo_program(const std::string& text);

#endif
