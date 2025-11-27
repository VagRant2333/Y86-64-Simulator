#ifndef CPU_H
#define CPU_H

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
    
    int pc_index;
    
    std::string stat;
    std::string last_error;
    bool pc_overridden;

    void step();
    std::string snapshot();

    uint64_t get_reg_val(const std::string& reg);
    void set_reg_val(const std::string& reg, uint64_t val);
    uint64_t get_reg_val(int reg_id);
    void set_reg_val(int reg_id, uint64_t val);
    std::string reg_name(int id);
    int reg_id(const std::string& name);
    
    uint64_t read_qword(uint64_t addr);
    void write_qword(uint64_t addr, uint64_t val);
    void write_byte(uint64_t addr, uint8_t val);
    
    void push(uint64_t val);
    uint64_t pop();
    
    void update_flags(const std::string& op, uint64_t a, uint64_t b, uint64_t result);
    
    void op_halt(const std::vector<std::string>& args);
    void op_nop(const std::vector<std::string>& args);
    void op_rrmovq(const std::vector<std::string>& args);
    void op_irmovq(const std::vector<std::string>& args);
    void op_rmmovq(const std::vector<std::string>& args);
    void op_mrmovq(const std::vector<std::string>& args);
    void op_addq(const std::vector<std::string>& args);
    void op_subq(const std::vector<std::string>& args);
    void op_andq(const std::vector<std::string>& args);
    void op_xorq(const std::vector<std::string>& args);
    void op_orq(const std::vector<std::string>& args);
    void op_jmp(const std::vector<std::string>& args);
    void op_jle(const std::vector<std::string>& args);
    void op_jl(const std::vector<std::string>& args);
    void op_je(const std::vector<std::string>& args);
    void op_jne(const std::vector<std::string>& args);
    void op_jge(const std::vector<std::string>& args);
    void op_jg(const std::vector<std::string>& args);
    void op_call(const std::vector<std::string>& args);
    void op_ret(const std::vector<std::string>& args);
    void op_pushq(const std::vector<std::string>& args);
    void op_popq(const std::vector<std::string>& args);
    void op_cmovle(const std::vector<std::string>& args);
    void op_cmovl(const std::vector<std::string>& args);
    void op_cmove(const std::vector<std::string>& args);
    void op_cmovne(const std::vector<std::string>& args);
    void op_cmovge(const std::vector<std::string>& args);
    void op_cmovg(const std::vector<std::string>& args);

    void handle_jump(const std::string& opcode, const std::vector<std::string>& args);
    void binary_op(const std::vector<std::string>& args, const std::string& op);
    
    uint64_t resolve_immediate(const std::string& token);
    std::pair<uint64_t, std::string> decode_memory(const std::string& operand);
    
    void error(const std::string& stat, const std::string& msg);
    int address_to_index(uint64_t addr);
    uint64_t current_address();
};

ProgramParseResult parse_yo_program(const std::string& text);

#endif
