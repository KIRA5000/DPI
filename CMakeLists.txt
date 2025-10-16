cmake_minimum_required(VERSION 3.15)
project(DPI LANGUAGES CXX)

# If the user doesn't supply a build type and this is a single-config
# generator (Makefiles, Ninja), default to Release.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(dpi main.cpp)

target_include_directories(dpi PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Prefer the portable Threads package instead of linking pthread directly
find_package(Threads REQUIRED)
target_link_libraries(dpi PRIVATE Threads::Threads)

# Common warning flags for all configurations
target_compile_options(dpi PRIVATE -Wall -Wextra)

# Per-configuration compile options using generator expressions
target_compile_options(dpi PRIVATE
	$<$<CONFIG:Debug>:-g -Og -DDEBUG -fno-omit-frame-pointer>
	$<$<CONFIG:RelWithDebInfo>:-O2 -g>
	$<$<CONFIG:Release>:-O3 -DNDEBUG -flto>
)

# Linker options for specific configs (Release LTO example)
target_link_options(dpi PRIVATE
	$<$<CONFIG:Release>:-flto>
)

# Export compile commands (useful for clangd, tooling)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optional install target
install(TARGETS dpi RUNTIME DESTINATION bin)