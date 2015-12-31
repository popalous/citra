#pragma once
#include <llvm/IR/IRBuilder.h>
#include <unordered_map>
#include <common/common_types.h>

enum class Register;

class InstructionBlock;
class MachineState;
class TBAA;
class BlockColors;

namespace llvm
{
    class Module;
}

class ModuleGen
{
public:
    /*
     * Verify - produce a code that can be verified
     *          this is done by returning after every opcode
     */
    explicit ModuleGen(llvm::Module *module, bool verify);
    ~ModuleGen();

    void Run();

    void GenerateIncInstructionCount();
    // Generate code to read pc and run all following instructions, used in cases of indirect branch
    void BranchReadPC();
    // Generate code to write to pc and run all following instructions, used in cases of direct branch
    void BranchWritePCConst(InstructionBlock *current, u64 pc);

    llvm::IRBuilder<> *IrBuilder() { return ir_builder.get(); }
    llvm::Module *Module() { return module; }
    MachineState *Machine() { return machine.get(); }
    TBAA *GetTBAA() { return tbaa.get(); }

private:
    // Generates the declarations of all the globals of the module
    void GenerateGlobals();
    void GenerateBlockAddressArray();
    void GenerateGetBlockAddressFunction();
    void GenerateCanRunFunction();
    void GenerateRunFunction();
    // Creates InstructionBlock for each instruction
    void DecodeInstructions();
    // Generates the entry basic blocks for each instruction
    void GenerateInstructionsEntry();
    // Generates the code of each instruction
    void GenerateInstructionsCode();
    // Must be run after the instruction code is generated since it depends on the
    // inter block jumps
    void ColorBlocks();

    llvm::Module *module;
    bool verify;

    std::unique_ptr<MachineState> machine;
    std::unique_ptr<TBAA> tbaa;

    std::unique_ptr<llvm::IRBuilder<>> ir_builder;

    size_t block_address_array_base;
    size_t block_address_array_size;
    /*
     * struct BlockAddress
     * {
     *     void (*function)(u32 index);
     *     u32 index;
     * }
     */
    llvm::StructType *block_address_type;
    llvm::Constant *block_address_not_present;
    /*
     * i8 **BlockAddressArray;
     *  The array at [i/4 - block_address_array_base] contains the block address for the instruction at i
     *  or nullptr if it is not decoded
     */
    llvm::ArrayType *block_address_array_type;
    llvm::GlobalVariable *block_address_array;
    /*
     * i32 InstructionCount;
     *  The count of instructions executed
     */
    llvm::GlobalVariable *instruction_count;
    /*
     * i8 *GetBlockAddress(u32 pc)
     *  Returns the address of the block for the instruction at pc
     */
    llvm::Function *get_block_address_function;
    /*
     * bool CanRun()
     *  Returns whether there is a binary translation available for a PC
     */
    llvm::Function *can_run_function;
    /*
     * void Run()
     *  Runs binary translated opcodes
     */
    llvm::Function *run_function;
    llvm::BasicBlock *run_function_entry;

    /*
     * All the instruction blocks
     */
    std::vector<std::unique_ptr<InstructionBlock>> instruction_blocks;
    std::unordered_map<u64, InstructionBlock *> instruction_blocks_by_pc;

    std::unique_ptr<BlockColors> block_colors;
};