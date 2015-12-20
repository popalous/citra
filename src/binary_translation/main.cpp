#include "common/logging/backend.h"
#include "common/logging/text_formatter.h"
#include "common/scope_exit.h"
#include "core/core.h"
#include "core/mem_map.h"
#include "core/hle/kernel/memory.h"
#include "core/loader/loader.h"
#include "code_gen.h"
#include <llvm/Support/CommandLine.h>

namespace cl = llvm::cl;

cl::opt<std::string> InputFilename(cl::Positional, cl::Required, cl::desc("<input rom filename>"));
cl::opt<std::string> OutputFilename(cl::Positional, cl::Required, cl::desc("<output object filename>"));
cl::opt<std::string> DebugFilename(cl::Positional, cl::Optional, cl::desc("<debug filename>"));
cl::opt<bool> Verify("verify", cl::desc("<verify>"), cl::init(false));

int main(int argc, const char *const *argv)
{
    // Remove all llvm options
    llvm::StringMap<cl::Option *>& options = cl::getRegisteredOptions();
    for (auto i = options.begin(); i != options.end(); ++i)
    {
        if (i->getValue() != &InputFilename && i->getValue() != &OutputFilename && i->getValue() != &DebugFilename)
        {
            i->getValue()->setHiddenFlag(cl::Hidden);
        }
    }
    cl::ParseCommandLineOptions(argc, argv);

    auto input_rom = InputFilename.c_str();
    auto output_object = OutputFilename.c_str();
    auto output_debug = DebugFilename.getNumOccurrences() ? DebugFilename.c_str() : nullptr;
    bool verify = Verify;

    Core::Init();
    Memory::Init();

    auto load_result = Loader::LoadFile(input_rom);
    if (Loader::ResultStatus::Success != load_result)
    {
        LOG_CRITICAL(BinaryTranslator, "Failed to load ROM (Error %i)!", load_result);
        return -1;
    }

    CodeGen code_generator(output_object, output_debug, verify);
    code_generator.Run();
}