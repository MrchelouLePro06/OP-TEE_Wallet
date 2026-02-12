cmake_minimum_required (VERSION 3.10)

project (optee_example_concurrency_test C)

set (CMAKE_C_STANDARD 99)

add_executable (optee_example_concurrency_test host/main.c)

# --- AJOUT CRITIQUE ---
# On dit à CMake de chercher les fichiers .h dans le dossier ta/include
target_include_directories(optee_example_concurrency_test PRIVATE ta/include)
# ----------------------

target_link_libraries (optee_example_concurrency_test teec)

install (TARGETS optee_example_concurrency_test DESTINATION ${CMAKE_INSTALL_BINDIR})
