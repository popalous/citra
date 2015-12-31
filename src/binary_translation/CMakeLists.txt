set(SRCS
            main.cpp
            code_gen.cpp
            module_gen.cpp
            disassembler.cpp
            instruction_block.cpp
            machine_state.cpp
            tbaa.cpp
            ARM_funcs.cpp
            block_colors.cpp

            instructions/instruction.cpp
            instructions/mov_shift.cpp
            instructions/branch.cpp
            instructions/arithmetic.cpp
            instructions/ldr.cpp
            instructions/str.cpp
            )
set(HEADERS
            code_gen.h
            module_gen.h
            disassembler.h
            instruction_block.h
            machine_state.h
            tbaa.h
            binary_search.h
            ARM_funcs.h
            block_colors.h

            instructions/types.h
            instructions/instruction.h
            instructions/mov_shift.h
            instructions/branch.h
            instructions/arithmetic.h
            instructions/ldr.h
            instructions/str.h
            )
create_directory_groups(${SRCS} ${HEADERS})

include_directories(.)
add_executable(binary_translate ${SRCS} ${HEADERS})
target_link_libraries(binary_translate ${llvm_libs})
target_link_libraries(binary_translate core common video_core)
target_link_libraries(binary_translate inih)
target_link_libraries(binary_translate ${PLATFORM_LIBRARIES})
