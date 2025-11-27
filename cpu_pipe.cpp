#include "cpu_pipe.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <cctype>
#include <cmath>
#include <regex>

using namespace std;


string REGS[] = {
    "%rax", "%rcx", "%rdx", "%rbx",
    "%rsp", "%rbp", "%rsi", "%rdi",
    "%r8", "%r9", "%r10", "%r11",
    "%r12", "%r13", "%r14", "%r15"
};


Y86CPU::Y86CPU(
    const vector<Instruction>& program,
    const map<string, uint64_t>& labels,
    const map<string, uint64_t>& initial_regs,
    const map<uint64_t, uint8_t>& initial_mem,
    const map<string, int>& initial_flags,
    uint64_t initial_pc) : program(program), labels(labels), memory(initial_mem), stat("AOK") {
    
    for (const auto& reg : REGS) registers[reg] = 0;
    for (const auto& pair : initial_regs) registers[pair.first] = pair.second & MASK64;
    
    if (initial_flags.count("ZF")) flags.ZF = initial_flags.at("ZF");
    if (initial_flags.count("SF")) flags.SF = initial_flags.at("SF");
    if (initial_flags.count("OF")) flags.OF = initial_flags.at("OF");
    
    for (size_t i = 0; i < program.size(); ++i) {
        addr_to_index[program[i].address] = i;
    }
    
    pc_index = address_to_index(initial_pc);
    
    F.predPC = initial_pc;
    f_predPC = initial_pc;
}



void Y86CPU::set_reg_val(int reg_id, uint64_t val) {
    if (reg_id >= 0 && reg_id < 15) registers[REGS[reg_id]] = val;
}

int Y86CPU::address_to_index(uint64_t addr) {
    if (program.empty()) return 0;
    if (addr_to_index.count(addr)) return addr_to_index[addr];
    if (addr < program.size()) return (int)addr;
    return 0;
}

uint64_t Y86CPU::current_address() {
    return F.predPC;
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
uint64_t Y86CPU::get_reg_val(const string& reg) {
    return registers[reg];
}

void Y86CPU::set_reg_val(const string& reg, uint64_t val) {
    registers[reg] = val & MASK64;
}

uint64_t Y86CPU::read_qword(uint64_t addr) {
    if (addr > MAX_ADDRESS - 7) {
        return 0;
    }
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        if (memory.count(addr + i))
            val |= (uint64_t)(memory[addr + i]) << (i * 8);
    }
    return val;
}

void Y86CPU::write_byte(uint64_t addr, uint8_t val) {
    if (addr > MAX_ADDRESS) {
        return;
    }
    memory[addr] = val;
}

void Y86CPU::write_qword(uint64_t addr, uint64_t val) {
    if (addr > MAX_ADDRESS - 7) {
        return;
    }
    for (int i = 0; i < 8; ++i) {
        memory[addr + i] = (val >> (i * 8)) & 0xFF;
    }
}

void Y86CPU::error(const string& s, const string& msg) {
    stat = s;
    last_error = msg;
}

uint64_t Y86CPU::resolve_immediate(const string& token) {
    string val = token;
    // remove leading whitespace
    val.erase(0, val.find_first_not_of(" \t"));
    // remove trailing whitespace
    val.erase(val.find_last_not_of(" \t") + 1);
    
    if (val.empty()) return 0;
    if (val[0] == '$') val = val.substr(1);
    
    if (labels.count(val)) return labels.at(val);
    
    try {
        if (val.find("0x") == 0 || val.find("0X") == 0) return stoull(val, nullptr, 16);
        return stoull(val, nullptr, 0);
    } catch (...) {
        // label arg to deal with L1+8 etc
        size_t plus = val.find('+');
        if (plus != string::npos) {
            string base = val.substr(0, plus);
            string offset = val.substr(plus + 1);
            // ver2: trim base and offset
            base.erase(0, base.find_first_not_of(" \t")); base.erase(base.find_last_not_of(" \t") + 1);
            offset.erase(0, offset.find_first_not_of(" \t")); offset.erase(offset.find_last_not_of(" \t") + 1);
            
            if (labels.count(base)) return labels.at(base) + stoull(offset, nullptr, 0);
        }
        size_t minus = val.find('-');
        if (minus != string::npos && minus != 0) {
             string base = val.substr(0, minus);
             string offset = val.substr(minus + 1);

             base.erase(0, base.find_first_not_of(" \t")); base.erase(base.find_last_not_of(" \t") + 1);
             offset.erase(0, offset.find_first_not_of(" \t")); offset.erase(offset.find_last_not_of(" \t") + 1);
             
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
        
        // disp
        disp_str.erase(0, disp_str.find_first_not_of(" \t"));
        if (!disp_str.empty()) disp_str.erase(disp_str.find_last_not_of(" \t") + 1);
        
        uint64_t disp = disp_str.empty() ? 0 : resolve_immediate(disp_str);
        return {disp, base_str};
    }
    return {resolve_immediate(operand), ""};
}

// ========================= core logic ====================================

void Y86CPU::writeback() {
    // check W.stat
    // except for ADR?...
    // update registers if stat is AOK
    
    if (W.stat == 1) {
        if (W.dstE != 15) set_reg_val(W.dstE, W.valE);
        if (W.dstM != 15) set_reg_val(W.dstM, W.valM);
    } else if (W.stat == 3) {
       if (W.dstE != 15) set_reg_val(W.dstE, W.valE);
    }
}

void Y86CPU::decode() {
    E_in.stat = D.stat;
    E_in.icode = D.icode;
    E_in.ifun = D.ifun;
    E_in.valC = D.valC;
    E_in.valP = D.valP;
    E_in.PC = D.PC;
    
    int srcA = 15;
    int srcB = 15;
    int dstE = 15;
    int dstM = 15;
    
    int icode = D.icode;
    int rA = D.rA;
    int rB = D.rB;
    
    // srcA
    if (icode == 2 || icode == 4 || icode == 6 || icode == 10) srcA = rA; // rrmovq, rmmovq, OPq, pushq
    else if (icode == 11 || icode == 9) srcA = 4; // popq, ret rsp
    
    // srcB
    if (icode == 6 || icode == 4 || icode == 5) srcB = rB; // OPq, rmmovq, mrmovq
    else if (icode == 10 || icode == 11 || icode == 8 || icode == 9) srcB = 4; // pushq, popq, call, ret rsp
    
    // dstE
    if (icode == 2) dstE = rB; // rrmovq
    else if (icode == 3) dstE = rB; // irmovq
    else if (icode == 6) dstE = rB; // OPq
    else if (icode == 10 || icode == 11 || icode == 8 || icode == 9) dstE = 4; // pushq, popq, call, ret rsp
    
    // dstM
    if (icode == 5 || icode == 11) dstM = rA; // mrmovq, popq
    
    E_in.srcA = srcA;
    E_in.srcB = srcB;
    E_in.dstE = dstE;
    E_in.dstM = dstM;
    uint64_t valA = get_reg_val(srcA);
    if (srcA != 15) { // forwarding
        if (srcA == M_in.dstE) valA = M_in.valE;
        else if (srcA == W_in.dstM) valA = W_in.valM;
        else if (srcA == W_in.dstE) valA = W_in.valE;
    }
    
    // call and jXX, valA is valP (return addr / next PC)

    if (icode == 8 || icode == 7) valA = D.valP;
    
    E_in.valA = valA;

    uint64_t valB = get_reg_val(srcB);
    if (srcB != 15) {
        if (srcB == M_in.dstE) valB = M_in.valE;
        else if (srcB == W_in.dstM) valB = W_in.valM;
        else if (srcB == W_in.dstE) valB = W_in.valE;
    }
    E_in.valB = valB;
    
    if ((E.icode == 5 || E.icode == 11) && (E.dstM == srcA || E.dstM == srcB)) {
        F.stall = true;
        D.stall = true;
        E_in.bubble = true;
    } else {
        F.stall = false;
        D.stall = false;
        E_in.bubble = false;
    }
}

void Y86CPU::execute() {
    M_in.stat = E.stat;
    M_in.icode = E.icode;
    M_in.valA = E.valA;
    M_in.dstM = E.dstM;
    M_in.PC = E.PC;
    M_in.valP = E.valP;
    
    int icode = E.icode;
    int ifun = E.ifun;
    uint64_t valA = E.valA;
    uint64_t valB = E.valB;
    uint64_t valC = E.valC;
    
    // ALU 
    uint64_t aluA = 0;
    uint64_t aluB = 0;
    int alufun = 0;
    

    if (icode == 2 || icode == 6) aluA = valA; 
    else if (icode == 3 || icode == 4 || icode == 5) aluA = valC; 
    else if (icode == 8 || icode == 10) aluA = -8; 
    else if (icode == 9 || icode == 11) aluA = 8; 
    
    if (icode == 4 || icode == 5 || icode == 6 || icode == 8 || icode == 9 || icode == 10 || icode == 11) aluB = valB;
    else if (icode == 2 || icode == 3) aluB = 0; 
    

    if (icode == 6) alufun = ifun;
    else alufun = 0; 

    uint64_t valE = 0;
    if (alufun == 0) valE = aluB + aluA;
    else if (alufun == 1) valE = aluB - aluA;
    else if (alufun == 2) valE = aluB & aluA;
    else if (alufun == 3) valE = aluB ^ aluA;
    

    bool exception = (W.stat != 1 || W_in.stat != 1);
    if (icode == 6 && !exception) {
        flags.ZF = (valE == 0);
        flags.SF = ((int64_t)valE < 0);
        int64_t sa = (int64_t)aluA;
        int64_t sb = (int64_t)aluB;
        int64_t sr = (int64_t)valE;
        // of
        if (alufun == 0) flags.OF = ((sa < 0 && sb < 0 && sr >= 0) || (sa >= 0 && sb >= 0 && sr < 0));
        else if (alufun == 1) flags.OF = ((sb < 0 && sa >= 0 && sr >= 0) || (sb >= 0 && sa < 0 && sr < 0));
        else flags.OF = false;
    }

    bool Cnd = false;
    if (icode == 7 || icode == 2) {
        if (ifun == 0) Cnd = true; // jmp/rrmovq
        else if (ifun == 1) Cnd = (flags.SF != flags.OF) || flags.ZF; // le
        else if (ifun == 2) Cnd = (flags.SF != flags.OF); // l
        else if (ifun == 3) Cnd = flags.ZF; // e
        else if (ifun == 4) Cnd = !flags.ZF; // ne
        else if (ifun == 5) Cnd = (flags.SF == flags.OF); // ge
        else if (ifun == 6) Cnd = (flags.SF == flags.OF) && !flags.ZF; // g
    }
    
    M_in.Cnd = Cnd;
    M_in.valE = valE;
    
    // cmovXX
    if (icode == 2 && !Cnd) M_in.dstE = 15;
    else M_in.dstE = E.dstE;
}

void Y86CPU::memory1() {
    W_in.stat = M.stat;
    W_in.icode = M.icode;
    W_in.valE = M.valE;
    W_in.dstE = M.dstE;
    W_in.dstM = M.dstM;
    W_in.PC = M.PC;
    W_in.valP = M.valP;
    
    int icode = M.icode;
    uint64_t mem_addr = 0;
    uint64_t mem_data = 0;
    bool mem_read = false;
    bool mem_write = false;

    if (icode == 4 || icode == 10 || icode == 8) { // rmmovq, pushq, call
        mem_addr = M.valE;
        mem_data = M.valA;
        mem_write = true;
    } else if (icode == 5 || icode == 11 || icode == 9) { // mrmovq, popq, ret
        if (icode == 5) mem_addr = M.valE;
        else mem_addr = M.valA;
        mem_read = true;
    }
    
    uint64_t valM = 0;

    if (mem_read) {
        valM = read_qword(mem_addr);
        if (mem_addr > MAX_ADDRESS - 7) W_in.stat = 3;
    }

    if (mem_write) {
        write_qword(mem_addr, mem_data);
        if (mem_addr > MAX_ADDRESS - 7) W_in.stat = 3;
    }
    
    W_in.valM = valM;
}


void Y86CPU::fetch() {
    uint64_t f_pc = F.predPC;
    
    // read instruction byte from memory
    // get icode ifun
    uint8_t icode_ifun = 0;
    bool imem_error = false;
    if (memory.count(f_pc)) icode_ifun = memory[f_pc];
    else imem_error = true;
    
    int icode = (icode_ifun >> 4) & 0xF;
    int ifun = icode_ifun & 0xF;
    
     // stat 1 OK, 2 HLT, 3 ADR, 4 INS
    if (imem_error) {
        icode = 1;
        D_in.stat = 3;
    } else {
        D_in.stat = 1;
    }
    
    D_in.icode = icode;
    D_in.ifun = ifun;
    
    // valP, next instruction (PC++)
    uint64_t valP = f_pc + 1;
    
    // read reg
    // rrmovq, irmovq, rmmovq, mrmovq, OPq, pushq, popq
    if (icode == 2 || icode == 3 || icode == 4 || icode == 5 || icode == 6 || icode == 10 || icode == 11) {
        uint8_t rArB = 0;
        if (memory.count(valP)) rArB = memory[valP];
        D_in.rA = (rArB >> 4) & 0xF;
        D_in.rB = rArB & 0xF;
        valP++;
    } else {
        D_in.rA = 15;
        D_in.rB = 15;
    }
    
    // read valC
    // irmovq, rmmovq, mrmovq, jXX, call
    if (icode == 3 || icode == 4 || icode == 5 || icode == 7 || icode == 8) {
        uint64_t v = 0;
        for(int i=0; i<8; ++i) {
            if (memory.count(valP + i)) v |= ((uint64_t)memory[valP + i] << (i*8));
        }
        D_in.valC = v;
        valP += 8;
    } else {
        D_in.valC = 0;
    }
    
    D_in.valP = valP;
    D_in.PC = f_pc; // Store current PC
    
    // predict next PC
    // jXX call, predict the target address (valC)
    // else predict valP
    if (icode == 7 || icode == 8) {
        f_predPC = D_in.valC;
    } else {
        f_predPC = valP;
    }
    
    // halt check
    if (icode == 0) D_in.stat = 2;
}

void Y86CPU::update_pipereg() {
    // Load-Use Hazard do_decode, sets E_in.bubble.
    bool load_use = E_in.bubble;
    

    bool mispredicted = (E.icode == 7 && !M_in.Cnd);
    
    // if ret (9) is in D, E, or M stages, stall Fetch
    // else if we mispredicted,  D is wrong ,don't stall
    bool ret_hazard = ((D.icode == 9 && !mispredicted) || E.icode == 9 || M.icode == 9);
    if (mispredicted) {
        D.bubble = true;
        E_in.bubble = true;
        F.stall = false; 
    }
    
    if (ret_hazard) {
        F.stall = true; // stall Fetch
        // bubble D to insert NOP
        bool ret_stall_d = (D.icode == 9 && load_use);
        if (!ret_stall_d) D.bubble = true;
    }
    
    // change f_predPC
    if (W.icode == 9) {
        f_predPC = W.valM;
        D.bubble = true;
    } else if (mispredicted) {
        f_predPC = E.valP;
    }
    if (!F.stall) F.predPC = f_predPC;

    if (D.bubble) D = D_Register();
    else if (!D.stall) D = D_in;

    if (E_in.bubble) E = E_Register();
    else E = E_in;
    M = M_in;
    W = W_in;
}

void Y86CPU::step() {
    writeback();
    memory1();
    execute();
    decode();
    fetch();
    
    update_pipereg();
    
    if (W.stat != 1) {
        if (W.stat == 2) stat = "HLT";
        else if (W.stat == 3) stat = "ADR";
        else if (W.stat == 4) stat = "INS";
    }
}


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
    } else {
        writeback();
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
    uint64_t report_pc = W.valP;
    if (W.stat != 1) report_pc = W.PC;
    ss << "\"PC\":" << report_pc << ",";
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
    
    // Pipeline Registers
    ss << "\"PIPE\":{";
    ss << "\"F\":{\"predPC\":" << F.predPC << ",\"stall\":" << F.stall << "},";
    ss << "\"D\":{\"stat\":" << D.stat << ",\"icode\":" << D.icode << ",\"ifun\":" << D.ifun << ",\"rA\":" << D.rA << ",\"rB\":" << D.rB << ",\"valC\":" << D.valC << ",\"valP\":" << D.valP << ",\"bubble\":" << D.bubble << ",\"stall\":" << D.stall << "},";
    ss << "\"E\":{\"stat\":" << E.stat << ",\"icode\":" << E.icode << ",\"ifun\":" << E.ifun << ",\"valC\":" << E.valC << ",\"valA\":" << E.valA << ",\"valB\":" << E.valB << ",\"dstE\":" << E.dstE << ",\"dstM\":" << E.dstM << ",\"srcA\":" << E.srcA << ",\"srcB\":" << E.srcB << ",\"bubble\":" << E.bubble << ",\"stall\":" << E.stall << "},";
    ss << "\"M\":{\"stat\":" << M.stat << ",\"icode\":" << M.icode << ",\"Cnd\":" << M.Cnd << ",\"valE\":" << M.valE << ",\"valA\":" << M.valA << ",\"valP\":" << M.valP << ",\"PC\":" << M.PC << ",\"dstE\":" << M.dstE << ",\"dstM\":" << M.dstM << ",\"bubble\":" << M.bubble << ",\"stall\":" << M.stall << "},";
    ss << "\"W\":{\"stat\":" << W.stat << ",\"icode\":" << W.icode << ",\"valE\":" << W.valE << ",\"valM\":" << W.valM << ",\"valP\":" << W.valP << ",\"PC\":" << W.PC << ",\"dstE\":" << W.dstE << ",\"dstM\":" << W.dstM << ",\"bubble\":" << W.bubble << ",\"stall\":" << W.stall << "}";
    ss << "},";

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
        asm_part.erase(0, asm_part.find_first_not_of(" \t"));
        if (asm_part.empty()) continue;
        asm_part.erase(asm_part.find_last_not_of(" \t") + 1);
        
        if (asm_part.empty()) continue;
        
        // Handle labels in assembly part (e.g. "Loop: jmp Loop")
        size_t label_colon = asm_part.find(':');
        if (label_colon != string::npos) {
            string label = asm_part.substr(0, label_colon);
            // Trim label
            label.erase(0, label.find_first_not_of(" \t"));
            if (!label.empty()) label.erase(label.find_last_not_of(" \t") + 1);
            
            if (!label.empty()) res.labels[label] = addr;
            
            asm_part = asm_part.substr(label_colon + 1);
            // Trim again
            asm_part.erase(0, asm_part.find_first_not_of(" \t"));
            if (asm_part.empty()) continue;
            asm_part.erase(asm_part.find_last_not_of(" \t") + 1);
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
            arg.erase(0, arg.find_first_not_of(" \t"));
            if (!arg.empty()) arg.erase(arg.find_last_not_of(" \t") + 1);
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
    // cout << "debug end" << endl;
    ProgramParseResult parsed = parse_yo_program(raw);
    
    map<string, uint64_t> initial_regs;
    map<uint64_t, uint8_t> initial_mem;
    map<string, int> initial_flags;
    uint64_t initial_pc = 0;
    
    // load memory
    for (auto const& [addr, val] : parsed.memory) {
        initial_mem[addr] = val;
    }
    
    Y86CPU cpu(parsed.instructions, parsed.labels, initial_regs, initial_mem, initial_flags, initial_pc);
    cout << cpu.run() << endl;
    
    return 0;
}
