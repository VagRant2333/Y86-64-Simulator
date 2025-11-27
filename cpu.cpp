#include "cpu.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <set>
#include <cctype>
#include <cmath>

using namespace std;

string REGS[] = {
    "%rax", "%rcx", "%rdx", "%rbx",
    "%rsp", "%rbp", "%rsi", "%rdi",
    "%r8", "%r9", "%r10", "%r11",
    "%r12", "%r13", "%r14", "%r15"
};

Y86CPU::Y86CPU(const vector<Instruction>& program,
       const map<string, uint64_t>& labels,
       const map<string, uint64_t>& initial_regs,
       const map<uint64_t, uint8_t>& initial_mem,
       const map<string, int>& initial_flags,
       uint64_t initial_pc)
    : program(program), labels(labels), memory(initial_mem), stat("AOK"), pc_overridden(false) {
    
    for (const auto& reg : REGS) {
        registers[reg] = 0;
    }
    for (const auto& pair : initial_regs) {
        registers[pair.first] = pair.second & MASK64;
    }
    
    if (initial_flags.count("ZF")) flags.ZF = initial_flags.at("ZF");
    if (initial_flags.count("SF")) flags.SF = initial_flags.at("SF");
    if (initial_flags.count("OF")) flags.OF = initial_flags.at("OF");
    
    for (size_t i = 0; i < program.size(); ++i) {
        addr_to_index[program[i].address] = i;
    }
    
    pc_index = address_to_index(initial_pc);
}

int Y86CPU::address_to_index(uint64_t addr) {
    if (program.empty()) return 0;
    if (addr_to_index.count(addr)) return addr_to_index[addr];
    if (addr < program.size()) return (int)addr;
    return 0;
}

uint64_t Y86CPU::current_address() {
    if (pc_index >= 0 && pc_index < (int)program.size()) {
        return program[pc_index].address;
    }
    return 0;
}

int Y86CPU::reg_id(const string& name) {
    for(int i=0; i<16; ++i) {
        if (REGS[i] == name) return i;
    }
    return 15;
}

string Y86CPU::reg_name(int id) {
    if (id >= 0 && id < 16) return REGS[id];
    return "none";
}

uint64_t Y86CPU::get_reg_val(int reg_id) {
    if (reg_id >= 0 && reg_id < 15) return registers[REGS[reg_id]];
    return 0;
}

void Y86CPU::set_reg_val(int reg_id, uint64_t val) {
    if (reg_id >= 0 && reg_id < 15) registers[REGS[reg_id]] = val;
}

uint64_t Y86CPU::get_reg_val(const string& reg) {
    return registers[reg];
}

void Y86CPU::set_reg_val(const string& reg, uint64_t val) {
    registers[reg] = val & MASK64;
}

uint64_t Y86CPU::read_qword(uint64_t addr) {
    if (addr > MAX_ADDRESS - 7) {
        error("ADR", "Invalid address");
        return 0;
    }
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= (uint64_t)(memory[addr + i]) << (i * 8);
    }
    return val;
}

void Y86CPU::write_byte(uint64_t addr, uint8_t val) {
    if (addr > MAX_ADDRESS) {
        error("ADR", "Invalid address");
        return;
    }
    memory[addr] = val;
}

void Y86CPU::write_qword(uint64_t addr, uint64_t val) {
    if (addr > MAX_ADDRESS - 7) {
        error("ADR", "Invalid address");
        return;
    }
    for (int i = 0; i < 8; ++i) {
        memory[addr + i] = (val >> (i * 8)) & 0xFF;
    }
}

void Y86CPU::push(uint64_t val) {
    uint64_t rsp = get_reg_val("%rsp");
    uint64_t new_rsp = rsp - 8;
    set_reg_val("%rsp", new_rsp);
    write_qword(new_rsp, val);
}

uint64_t Y86CPU::pop() {
    uint64_t rsp = get_reg_val("%rsp");
    uint64_t val = read_qword(rsp);
    if (stat != "AOK") return 0;
    set_reg_val("%rsp", rsp + 8);
    return val;
}

void Y86CPU::error(const string& s, const string& msg) {
    stat = s;
    last_error = msg;
}

void Y86CPU::update_flags(const string& op, uint64_t a, uint64_t b, uint64_t result) {
    flags.ZF = (result == 0);
    flags.SF = ((result >> 63) & 1);
    
    int64_t sa = (int64_t)a;
    int64_t sb = (int64_t)b;
    int64_t sr = (int64_t)result;
    
    if (op == "addq") {
        flags.OF = ((sa < 0 && sb < 0 && sr >= 0) || (sa >= 0 && sb >= 0 && sr < 0));
    } else if (op == "subq") {
        flags.OF = ((sb < 0 && sa >= 0 && sr >= 0) || (sb >= 0 && sa < 0 && sr < 0));
    } else {
        flags.OF = false;
    }
}

uint64_t Y86CPU::resolve_immediate(const string& token) {
    string val = token;
    // remove leading whitespace
    val.erase(0, val.find_first_not_of(" \t\r\n"));
    // remove trailing whitespace
    if (!val.empty()) val.erase(val.find_last_not_of(" \t\r\n") + 1);
    
    if (val.empty()) return 0;
    if (val[0] == '$') val = val.substr(1);
    
    if (labels.count(val)) return labels.at(val);
    
    try {
        if (val.find("0x") == 0 || val.find("0X") == 0) {
            return stoull(val, nullptr, 0);
        }
        return stoull(val, nullptr, 0);
    } catch (...) {
        size_t plus = val.find('+');
        if (plus != string::npos) {
            string base = val.substr(0, plus);
            string offset = val.substr(plus + 1);
            base.erase(0, base.find_first_not_of(" \t\r\n")); if(!base.empty()) base.erase(base.find_last_not_of(" \t\r\n") + 1);
            offset.erase(0, offset.find_first_not_of(" \t\r\n")); if(!offset.empty()) offset.erase(offset.find_last_not_of(" \t\r\n") + 1);
            if (labels.count(base)) return labels.at(base) + stoull(offset, nullptr, 0);
        }
        size_t minus = val.find('-');
        if (minus != string::npos && minus != 0) {
             string base = val.substr(0, minus);
             string offset = val.substr(minus + 1);
             base.erase(0, base.find_first_not_of(" \t\r\n")); if(!base.empty()) base.erase(base.find_last_not_of(" \t\r\n") + 1);
             offset.erase(0, offset.find_first_not_of(" \t\r\n")); if(!offset.empty()) offset.erase(offset.find_last_not_of(" \t\r\n") + 1);
             if (labels.count(base)) return labels.at(base) - stoull(offset, nullptr, 0);
        }
    }
    return 0;
}

pair<uint64_t, string> Y86CPU::decode_memory(const string& operand) {
    size_t lparen = operand.find('(');
    size_t rparen = operand.find(')');
    
    if (lparen != string::npos && rparen != string::npos && rparen > lparen) {
        string disp_str = operand.substr(0, lparen);
        string base_str = operand.substr(lparen + 1, rparen - lparen - 1);
        
        disp_str.erase(0, disp_str.find_first_not_of(" \t\r\n"));
        if (!disp_str.empty()) disp_str.erase(disp_str.find_last_not_of(" \t\r\n") + 1);
        
        base_str.erase(0, base_str.find_first_not_of(" \t\r\n"));
        if (!base_str.empty()) base_str.erase(base_str.find_last_not_of(" \t\r\n") + 1);

        uint64_t disp = disp_str.empty() ? 0 : resolve_immediate(disp_str);
        return {disp, base_str};
    }
    return {resolve_immediate(operand), ""};
}

void Y86CPU::step() {
    if (stat != "AOK") return;
    if (pc_index < 0 || pc_index >= (int)program.size()) {
        error("ADR", "PC out of range");
        return;
    }
    
    const Instruction& inst = program[pc_index];
    pc_overridden = false;
    
    int op = 0;
    if (inst.opcode == "halt") op = 1;
    else if (inst.opcode == "nop") op = 2;
    else if (inst.opcode == "rrmovq") op = 3;
    else if (inst.opcode == "irmovq") op = 4;
    else if (inst.opcode == "rmmovq") op = 5;
    else if (inst.opcode == "mrmovq") op = 6;
    else if (inst.opcode == "addq") op = 7;
    else if (inst.opcode == "subq") op = 8;
    else if (inst.opcode == "andq") op = 9;
    else if (inst.opcode == "xorq") op = 10;
    else if (inst.opcode == "orq") op = 11;
    else if (inst.opcode == "jmp") op = 12;
    else if (inst.opcode == "jle") op = 13;
    else if (inst.opcode == "jl") op = 14;
    else if (inst.opcode == "je") op = 15;
    else if (inst.opcode == "jne") op = 16;
    else if (inst.opcode == "jge") op = 17;
    else if (inst.opcode == "jg") op = 18;
    else if (inst.opcode == "call") op = 19;
    else if (inst.opcode == "ret") op = 20;
    else if (inst.opcode == "pushq") op = 21;
    else if (inst.opcode == "popq") op = 22;
    else if (inst.opcode == "cmovle") op = 23;
    else if (inst.opcode == "cmovl") op = 24;
    else if (inst.opcode == "cmove") op = 25;
    else if (inst.opcode == "cmovne") op = 26;
    else if (inst.opcode == "cmovge") op = 27;
    else if (inst.opcode == "cmovg") op = 28;

    switch (op) {
        case 1: op_halt(inst.args); break;
        case 2: op_nop(inst.args); break;
        case 3: op_rrmovq(inst.args); break;
        case 4: op_irmovq(inst.args); break;
        case 5: op_rmmovq(inst.args); break;
        case 6: op_mrmovq(inst.args); break;
        case 7: op_addq(inst.args); break;
        case 8: op_subq(inst.args); break;
        case 9: op_andq(inst.args); break;
        case 10: op_xorq(inst.args); break;
        case 11: op_orq(inst.args); break;
        case 12: op_jmp(inst.args); break;
        case 13: op_jle(inst.args); break;
        case 14: op_jl(inst.args); break;
        case 15: op_je(inst.args); break;
        case 16: op_jne(inst.args); break;
        case 17: op_jge(inst.args); break;
        case 18: op_jg(inst.args); break;
        case 19: op_call(inst.args); break;
        case 20: op_ret(inst.args); break;
        case 21: op_pushq(inst.args); break;
        case 22: op_popq(inst.args); break;
        case 23: op_cmovle(inst.args); break;
        case 24: op_cmovl(inst.args); break;
        case 25: op_cmove(inst.args); break;
        case 26: op_cmovne(inst.args); break;
        case 27: op_cmovge(inst.args); break;
        case 28: op_cmovg(inst.args); break;
        default: error("INS", "Invalid instruction"); break;
    }
    
    if (stat == "AOK" && !pc_overridden) {
        pc_index++;
    }
}

void Y86CPU::op_halt(const vector<string>&) { stat = "HLT"; pc_overridden = true; }
void Y86CPU::op_nop(const vector<string>&) {}

void Y86CPU::op_rrmovq(const vector<string>& args) {
    set_reg_val(args[1], get_reg_val(args[0]));
}

void Y86CPU::op_irmovq(const vector<string>& args) {
    set_reg_val(args[1], resolve_immediate(args[0]));
}

void Y86CPU::op_rmmovq(const vector<string>& args) {
    uint64_t val = get_reg_val(args[0]);
    auto [disp, base] = decode_memory(args[1]);
    uint64_t base_val = base.empty() ? 0 : get_reg_val(base);
    write_qword(base_val + disp, val);
}

void Y86CPU::op_mrmovq(const vector<string>& args) {
    auto [disp, base] = decode_memory(args[0]);
    uint64_t base_val = base.empty() ? 0 : get_reg_val(base);
    uint64_t val = read_qword(base_val + disp);
    if (stat == "AOK") set_reg_val(args[1], val);
}

void Y86CPU::binary_op(const vector<string>& args, const string& op) {
    uint64_t src = get_reg_val(args[0]);
    uint64_t dst_val = get_reg_val(args[1]);
    uint64_t result = 0;
    if (op == "addq") result = dst_val + src;
    else if (op == "subq") result = dst_val - src;
    else if (op == "andq") result = dst_val & src;
    else if (op == "xorq") result = dst_val ^ src;
    else if (op == "orq") result = dst_val | src;
    
    set_reg_val(args[1], result);
    update_flags(op, src, dst_val, result);
}

void Y86CPU::op_addq(const vector<string>& args) { binary_op(args, "addq"); }
void Y86CPU::op_subq(const vector<string>& args) { binary_op(args, "subq"); }
void Y86CPU::op_andq(const vector<string>& args) { binary_op(args, "andq"); }
void Y86CPU::op_xorq(const vector<string>& args) { binary_op(args, "xorq"); }
void Y86CPU::op_orq(const vector<string>& args) { binary_op(args, "orq"); }

void Y86CPU::handle_jump(const string& opcode, const vector<string>& args) {
    bool take = false;
    if (opcode == "jmp") take = true;
    else if (opcode == "jle") take = (flags.SF != flags.OF) || flags.ZF;
    else if (opcode == "jl") take = (flags.SF != flags.OF);
    else if (opcode == "je") take = flags.ZF;
    else if (opcode == "jne") take = !flags.ZF;
    else if (opcode == "jge") take = (flags.SF == flags.OF);
    else if (opcode == "jg") take = (flags.SF == flags.OF) && !flags.ZF;
    
    if (take) {
        string target = args[0];
        if (labels.count(target)) {
            pc_index = address_to_index(labels[target]);
            pc_overridden = true;
        } else {
            uint64_t addr = resolve_immediate(target);
            pc_index = address_to_index(addr);
            pc_overridden = true;
        }
    }
}

void Y86CPU::op_jmp(const vector<string>& args) { handle_jump("jmp", args); }
void Y86CPU::op_jle(const vector<string>& args) { handle_jump("jle", args); }
void Y86CPU::op_jl(const vector<string>& args) { handle_jump("jl", args); }
void Y86CPU::op_je(const vector<string>& args) { handle_jump("je", args); }
void Y86CPU::op_jne(const vector<string>& args) { handle_jump("jne", args); }
void Y86CPU::op_jge(const vector<string>& args) { handle_jump("jge", args); }
void Y86CPU::op_jg(const vector<string>& args) { handle_jump("jg", args); }

void Y86CPU::op_call(const vector<string>& args) {
    uint64_t ret_addr = 0;
    if (pc_index + 1 < (int)program.size()) ret_addr = program[pc_index + 1].address;
    else ret_addr = program[pc_index].address + 1; 
    
    push(ret_addr);
    handle_jump("jmp", args);
}

void Y86CPU::op_ret(const vector<string>&) {
    uint64_t ret_addr = pop();
    pc_index = address_to_index(ret_addr);
    pc_overridden = true;
}

void Y86CPU::op_pushq(const vector<string>& args) { push(get_reg_val(args[0])); }
void Y86CPU::op_popq(const vector<string>& args) { set_reg_val(args[0], pop()); }

void Y86CPU::op_cmovle(const vector<string>& args) { if ((flags.SF != flags.OF) || flags.ZF) set_reg_val(args[1], get_reg_val(args[0])); }
void Y86CPU::op_cmovl(const vector<string>& args) { if (flags.SF != flags.OF) set_reg_val(args[1], get_reg_val(args[0])); }
void Y86CPU::op_cmove(const vector<string>& args) { if (flags.ZF) set_reg_val(args[1], get_reg_val(args[0])); }
void Y86CPU::op_cmovne(const vector<string>& args) { if (!flags.ZF) set_reg_val(args[1], get_reg_val(args[0])); }
void Y86CPU::op_cmovge(const vector<string>& args) { if (flags.SF == flags.OF) set_reg_val(args[1], get_reg_val(args[0])); }
void Y86CPU::op_cmovg(const vector<string>& args) { if ((flags.SF == flags.OF) && !flags.ZF) set_reg_val(args[1], get_reg_val(args[0])); }



string Y86CPU::run() {
    stringstream ss;
    ss << "[";

    bool first = true;
    while (stat == "AOK") {
        step();
        if (!first) ss << ",";
        ss << snapshot();
        first = false;
    }
    if (stat == "AOK") {
        stat = "INS";
        if (!first) ss << ",";
        ss << snapshot();
    }
    ss << "]";
    return ss.str();
}


// ==== From here to bottom ====
// == codes are generated by Gemini 3 Pro and then modified ==

string Y86CPU::snapshot() {
    stringstream ss;
    ss << "{";
    ss << "\"PC\":" << current_address() << ",";
    ss << "\"REG\":{";
    for (int i = 0; i < 15; ++i) { // Output 0-14 (exclude r15)
        string name = REGS[i].substr(1); // Remove '%'
        ss << "\"" << name << "\":" << (int64_t)registers[REGS[i]];
        if (i < 14) ss << ",";
    }
    ss << "},";
    ss << "\"CC\":{\"ZF\":" << flags.ZF << ",\"SF\":" << flags.SF << ",\"OF\":" << flags.OF << "},";
    
    int stat_code = 4; 
    if (stat == "AOK") stat_code = 1;
    else if (stat == "HLT") stat_code = 2;
    else if (stat == "ADR") stat_code = 3;
    else if (stat == "INS") stat_code = 4;
    ss << "\"STAT\":" << stat_code << ",";
    
    ss << "\"MEM\":{";
    bool first = true;
    uint64_t current_word_addr = (uint64_t)-1; // Invalid address
    uint64_t current_word_val = 0;
    bool has_pending = false;

    for (auto const& [addr, val] : memory) {
        uint64_t word_addr = addr & ~7ULL;
        if (word_addr != current_word_addr) {
            if (has_pending) {
                if (current_word_val != 0) {
                    if (!first) ss << ",";
                    ss << "\"" << current_word_addr << "\":" << (int64_t)current_word_val;
                    first = false;
                }
            }
            current_word_addr = word_addr;
            current_word_val = 0;
            has_pending = true;
        }
        uint64_t shift = (addr % 8) * 8;
        current_word_val |= ((uint64_t)val << shift);
    }
    
    if (has_pending) {
        if (current_word_val != 0) {
            if (!first) ss << ",";
            ss << "\"" << current_word_addr << "\":" << (int64_t)current_word_val;
        }
    }
    ss << "}";
    ss << "}";
    return ss.str();
}

ProgramParseResult parse_yo_program(const string& text) {
    ProgramParseResult res;
    istringstream iss(text);
    string line;
    int line_num = 0;
    
    while (getline(iss, line)) {
        line_num++;
        
        // Find "0x"
        size_t ox = line.find("0x");
        if (ox == string::npos) continue;
        
        // Parse address
        size_t colon = line.find(':', ox);
        if (colon == string::npos) continue;
        
        string addr_str = line.substr(ox, colon - ox);
        uint64_t addr = 0;
        try {
            addr = stoull(addr_str, nullptr, 16);
        } catch (...) { continue; }
        
        // Parse hex bytes
        size_t pipe = line.find('|');
        if (pipe == string::npos) continue;
        
        string hex_part = line.substr(colon + 1, pipe - (colon + 1));
        // Remove whitespace
        hex_part.erase(remove_if(hex_part.begin(), hex_part.end(), ::isspace), hex_part.end());
        
        if (!hex_part.empty()) {
            for (size_t i = 0; i < hex_part.length(); i += 2) {
                if (i + 1 >= hex_part.length()) break;
                string byte_str = hex_part.substr(i, 2);
                try {
                    uint8_t byte = (uint8_t)stoul(byte_str, nullptr, 16);
                    res.memory[addr + i/2] = byte;
                } catch (...) {}
            }
        }
        
        // Parse assembly (optional, for debug/trace)
        string asm_part = line.substr(pipe + 1);
        // Remove comments
        size_t comment = asm_part.find('#');
        if (comment != string::npos) asm_part = asm_part.substr(0, comment);
        
        // Trim
        asm_part.erase(0, asm_part.find_first_not_of(" \t\r\n"));
        if (asm_part.empty()) continue;
        asm_part.erase(asm_part.find_last_not_of(" \t\r\n") + 1);
        
        if (asm_part.empty()) continue;
        
        // Handle labels in assembly part (e.g. "Loop: jmp Loop")
        size_t label_colon = asm_part.find(':');
        if (label_colon != string::npos) {
            string label = asm_part.substr(0, label_colon);
            // Trim label
            label.erase(0, label.find_first_not_of(" \t\r\n"));
            if (!label.empty()) label.erase(label.find_last_not_of(" \t\r\n") + 1);
            
            if (!label.empty()) res.labels[label] = addr;
            
            asm_part = asm_part.substr(label_colon + 1);
            // Trim again
            asm_part.erase(0, asm_part.find_first_not_of(" \t\r\n"));
            if (asm_part.empty()) continue;
            asm_part.erase(asm_part.find_last_not_of(" \t\r\n") + 1);
        }
        
        if (asm_part.empty() || asm_part[0] == '.') continue;

        Instruction inst;
        inst.address = addr;
        inst.line = line_num;
        inst.source = line; // Keep full line for debug
        
        // Parse opcode and args
        istringstream asm_ss(asm_part);
        string opcode;
        asm_ss >> opcode;
        inst.opcode = opcode;
        // Lowercase opcode
        transform(inst.opcode.begin(), inst.opcode.end(), inst.opcode.begin(), ::tolower);
        
        string args_part;
        getline(asm_ss, args_part);
        
        // Split args by comma
        string arg;
        istringstream args_ss(args_part);
        while (getline(args_ss, arg, ',')) {
            // Trim arg
            arg.erase(0, arg.find_first_not_of(" \t\r\n"));
            if (!arg.empty()) arg.erase(arg.find_last_not_of(" \t\r\n") + 1);
            if (!arg.empty()) inst.args.push_back(arg);
        }
        
        res.instructions.push_back(inst);
    }
    
    // Sort instructions
    sort(res.instructions.begin(), res.instructions.end(), [](const Instruction& a, const Instruction& b) {
        return a.address < b.address;
    });
    
    return res;
}

int main() {
    string raw((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>());
    
    if (raw.empty()) {
        cout << "[]" << endl;
        return 0;
    }
    
    ProgramParseResult parsed = parse_yo_program(raw);
    
    map<string, uint64_t> initial_regs;
    map<uint64_t, uint8_t> initial_mem;
    map<string, int> initial_flags;
    uint64_t initial_pc = 0;
    
    // Load memory from parsed result
    for (auto const& [addr, val] : parsed.memory) {
        initial_mem[addr] = val;
    }
    
    Y86CPU cpu(parsed.instructions, parsed.labels, initial_regs, initial_mem, initial_flags, initial_pc);
    cout << cpu.run() << endl;
    
    return 0;
}
