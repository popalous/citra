#include "code_gen.h"
#include "module_gen.h"

#include "core/loader/loader.h"
#include "common/logging/log.h"

#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Host.h>
#include <llvm/Target/TargetSubtargetInfo.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/IPO.h>
#include <iostream>

using namespace llvm;

CodeGen::CodeGen(const char* output_object_filename, const char* output_debug_filename, bool verify)
    : output_object_filename(output_object_filename),
      output_debug_filename(output_debug_filename),
      verify(verify)
{
}

CodeGen::~CodeGen()
{
}

void CodeGen::Run()
{
    if (!Loader::ROMCodeStart)
    {
        LOG_CRITICAL(BinaryTranslator, "No information from the loader about ROM file.");
        return;
    }

    InitializeLLVM();
    GenerateModule();
    GenerateDebugFiles();
    if (!Verify()) return;
    OptimizeAndGenerate();
}

void CodeGen::InitializeLLVM()
{
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();

    auto triple_string = sys::getProcessTriple();
#ifdef _WIN32
    // LLVM doesn't know how to load coff files
    // It can handle elf files in every platform
    triple_string += "-elf";
#endif

    triple = llvm::make_unique<Triple>(triple_string);

    // This engine builder is needed to get the target machine. It requires a module
    // but takes ownership of it so the main module cannot be passed here.
    EngineBuilder engine_builder(make_unique<Module>("", getGlobalContext()));
    target_machine.reset(engine_builder.selectTarget(*triple, "", "", SmallVector<std::string, 0>()));

    module = make_unique<Module>("Module", getGlobalContext());
    module->setTargetTriple(triple_string);
}

void CodeGen::GenerateModule()
{
    moduleGenerator = std::make_unique<ModuleGen>(module.get(), verify);
    moduleGenerator->Run();
}

void CodeGen::GenerateDebugFiles()
{
    if (!output_debug_filename) return;

    LOG_INFO(BinaryTranslator, "Writing debug file");
    std::ofstream file(output_debug_filename);
    if (!file)
    {
        LOG_ERROR(BinaryTranslator, "Cannot create debug file: %s", output_debug_filename);
        return;
    }
    raw_os_ostream stream(file);

    module->print(stream, nullptr);
    stream.flush();
    file.close();
    LOG_INFO(BinaryTranslator, "Done");
}

bool CodeGen::Verify()
{
    LOG_INFO(BinaryTranslator, "Verifying");
    raw_os_ostream os(std::cout);
    if (verifyModule(*module, &os))
    {
        LOG_CRITICAL(BinaryTranslator, "Verify failed");
        return false;
    }
    LOG_INFO(BinaryTranslator, "Done");
    return true;
}

void CodeGen::OptimizeAndGenerate()
{
    /*
     * Taken from opt for O3
     */
    PassManagerBuilder pass_manager_builder;

    legacy::FunctionPassManager function_pass_manager(module.get());
    legacy::PassManager pass_manager;

    module->setDataLayout(*target_machine->getDataLayout());

    pass_manager.add(createVerifierPass());
    pass_manager.add(new TargetLibraryInfoWrapperPass(*triple.get()));

    pass_manager_builder.OptLevel = 3;
    pass_manager_builder.SizeLevel = 0;
    pass_manager_builder.Inliner = createFunctionInliningPass(3, 0);
    pass_manager_builder.LoopVectorize = true;
    pass_manager_builder.SLPVectorize = true;

    pass_manager_builder.populateFunctionPassManager(function_pass_manager);

    pass_manager_builder.OptLevel = 1;
    pass_manager_builder.SizeLevel = 0;
    pass_manager_builder.LoopVectorize = false;
    pass_manager_builder.SLPVectorize = false;
    pass_manager_builder.populateModulePassManager(pass_manager);

    LOG_INFO(BinaryTranslator, "Optimizing functions");
    function_pass_manager.doInitialization();
    for (auto &function : *module)
        function_pass_manager.run(function);
    function_pass_manager.doFinalization();
    LOG_INFO(BinaryTranslator, "Done");

    pass_manager.add(createVerifierPass());

    MCContext *context;
    std::ofstream file(output_object_filename, std::ios::binary);
    if (!file)
    {
        LOG_CRITICAL(BinaryTranslator, "Cannot create object file: %s", output_object_filename);
        return;
    }
    raw_os_ostream fstream(file);
    buffer_ostream* stream = new buffer_ostream(fstream);

    if (target_machine->addPassesToEmitMC(pass_manager, context, *stream, false))
    {
        LOG_CRITICAL(BinaryTranslator, "Target does not support MC emission!");
        return;
    }
    LOG_INFO(BinaryTranslator, "Generating code");
    pass_manager.run(*module);
    stream->flush();
    delete stream;
    fstream.flush();
    file.close();
    LOG_INFO(BinaryTranslator, "Done");
}