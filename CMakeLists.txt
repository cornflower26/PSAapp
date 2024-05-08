cmake_minimum_required(VERSION 3.25)
project(SLAP)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lomp=libomp")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp -L/usr/local/Cellar/libomp/18.1.2/lib -I/usr/local/Cellar/libomp/18.1.2/include")

add_executable(SLAP main.cpp
        PSA-base-scheme.h
        PSA-constants.h
        slaprns-scheme.h
        PSA-cryptocontext.h
        dgsampler.h
        slaprns-scheme.cpp
        PSA-cryptocontext.cpp
        PSA-base-scheme.cpp
        utils.cpp)

add_library(openfhecorelib SHARED IMPORTED)
add_library(openfhepkelib SHARED IMPORTED)

set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEpke.so")
set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEcore.so")

include_directories("/usr/local/include/openfhe")
include_directories("/usr/local/include/openfhe/core")
include_directories("/usr/local/include/openfhe/pke")
include_directories("/usr/local/include/openfhe/binfhe")

link_directories("/usr/local/lib")
link_directories("/usr/include")

#target_link_libraries(SLAP omp)
target_link_libraries(SLAP OPENFHEcore)
target_link_libraries(SLAP OPENFHEpke)
target_link_libraries(SLAP OPENFHEbinfhe)

set(CMAKE_PREFIX_PATH "/usr/local/lib/OpenFHE")
find_package("OpenFHE")




