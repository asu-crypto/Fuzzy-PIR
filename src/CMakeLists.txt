cmake_minimum_required(VERSION 3.9.4)
project(fuzzy-pir)

set(CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 20)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

if(NOT DEFINED CRYPTO_TOOLS_INSTALL_PATH)
  set(CRYPTO_TOOLS_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../cryptoTools")
endif()

if(NOT DEFINED CATCH2_INSTALL_PATH)
  set(CATCH2_INSTALL_PATH "${CMAKE_SOURCE_DIR}/../catch2")
endif()

set (CMAKE_PREFIX_PATH "${CRYPTO_TOOLS_INSTALL_PATH};${CATCH2_INSTALL_PATH}")

find_package(Catch2 3 REQUIRED)
find_package(cryptoTools REQUIRED)
find_path(GMP_INCLUDE_DIR gmp.h)
find_library(GMP_LIBRARIES gmp)
find_library(GMPXX_LIBRARIES gmpxx)

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARIES)
    message(FATAL_ERROR "Could not find GMP library")
endif()

set(BUILD_PROFILING_EXECUTABLES OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -ftree-vectorize -fopt-info-vec-optimized")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O3 -Wall -Wextra -Wpedantic)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Profile")
  add_compile_options(-O3)
  add_compile_options(-pg)
  add_compile_options(-ftree-vectorizer-verbose=6)
  add_link_options(-pg)
  set(BUILD_PROFILING_EXECUTABLES ON)
  set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

message(CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

set(HEADERS
  ${CMAKE_SOURCE_DIR}/fss.hpp
  ${CMAKE_SOURCE_DIR}/utils.hpp
  ${CMAKE_SOURCE_DIR}/rand.hpp
  ${CMAKE_SOURCE_DIR}/paillier.hpp
  ${CMAKE_SOURCE_DIR}/ss.hpp
  ${CMAKE_SOURCE_DIR}/pal_hss.hpp
  ${CMAKE_SOURCE_DIR}/hss_hd.hpp
  ${CMAKE_SOURCE_DIR}/pk_hd_fss.hpp
  #${CMAKE_SOURCE_DIR}/ss_iblt.hpp
  ${CMAKE_SOURCE_DIR}/u8_ss_iblt.hpp
  ${CMAKE_SOURCE_DIR}/u64_ss_iblt.hpp
  ${CMAKE_SOURCE_DIR}/pk_fpir.hpp
)
set(SOURCES
  ${CMAKE_SOURCE_DIR}/fss.cpp
  ${CMAKE_SOURCE_DIR}/utils.cpp
  ${CMAKE_SOURCE_DIR}/rand.cpp
  ${CMAKE_SOURCE_DIR}/paillier.cpp
  ${CMAKE_SOURCE_DIR}/ss.cpp
  ${CMAKE_SOURCE_DIR}/pal_hss.cpp
  ${CMAKE_SOURCE_DIR}/hss_hd.cpp
  ${CMAKE_SOURCE_DIR}/pk_hd_fss.cpp
  ${CMAKE_SOURCE_DIR}/u8_ss_iblt.cpp
  #${CMAKE_SOURCE_DIR}/ss_iblt.cpp
  ${CMAKE_SOURCE_DIR}/u64_ss_iblt.cpp
  ${CMAKE_SOURCE_DIR}/u8_ss_iblt.cpp
  ${CMAKE_SOURCE_DIR}/pk_fpir.cpp
)

if( supported )
    message(STATUS "IPO / LTO enabled")
else()
    message(SEND_ERROR "IPO / LTO not supported: <${error}>")
endif()

if(BUILD_TESTS)
    set(ALL_TESTS
        dpf_test
        hdfss_test
        utils_test
        rand_test
        paillier_test
        ss_test
        pal_hss_test
        hss_hd_test
        pk_hd_fss_test
        #iblt_test
        pk_fpir_test
    )

    set (TEST_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/tests)

    add_executable(dpf_test ${TEST_SOURCE_PREFIX}/dpf.test.cpp ${SOURCES})
    add_executable(hdfss_test ${TEST_SOURCE_PREFIX}/hd_fss.test.cpp ${SOURCES})
    add_executable(utils_test ${TEST_SOURCE_PREFIX}/utils.test.cpp ${SOURCES})
    add_executable(rand_test ${TEST_SOURCE_PREFIX}/rand.test.cpp ${SOURCES})
    add_executable(paillier_test ${TEST_SOURCE_PREFIX}/paillier.test.cpp ${SOURCES})
    add_executable(ss_test ${TEST_SOURCE_PREFIX}/ss.test.cpp ${SOURCES})
    add_executable(pal_hss_test ${TEST_SOURCE_PREFIX}/pal_hss.test.cpp ${SOURCES})
    add_executable(hss_hd_test ${TEST_SOURCE_PREFIX}/hss_hd.test.cpp ${SOURCES})
    add_executable(pk_hd_fss_test ${TEST_SOURCE_PREFIX}/pk_hd_fss.test.cpp ${SOURCES})
    #add_executable(iblt_test ${TEST_SOURCE_PREFIX}/iblt.test.cpp ${SOURCES})
    add_executable(pk_fpir_test ${TEST_SOURCE_PREFIX}/pk_fpir.test.cpp ${SOURCES})

    foreach(target ${ALL_TESTS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
        target_include_directories(${target} PRIVATE ${GMP_INCLUDE_DIR})
        #target_compile_options(${target} PRIVATE ${GMP_CFLAGS_OTHER})

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()

if(BUILD_BENCH)
   set(ALL_BENCHS
        #psu_bench
        #simd_bench
        #ot_reduc
        #iblt_h5_bench
        #bitvector_bench
        #multiaes_bench
        #preprocessing_bench
        pk_fpir_bench
        sk_hd_fss_bench
        dpf_bench
        pk_hd_fss_bench
        ss_iblt_bench
    )

    set (BENCH_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/benchmarks)
    
    add_executable(pk_fpir_bench ${BENCH_SOURCE_PREFIX}/pk_fpir.bench.cpp ${SOURCES})
    add_executable(sk_hd_fss_bench ${BENCH_SOURCE_PREFIX}/sk_hd_fss.bench.cpp ${SOURCES})
    add_executable(dpf_bench ${BENCH_SOURCE_PREFIX}/dpf.bench.cpp ${SOURCES})
    add_executable(pk_hd_fss_bench ${BENCH_SOURCE_PREFIX}/pk_hd_fss.bench.cpp ${SOURCES})
    add_executable(ss_iblt_bench ${BENCH_SOURCE_PREFIX}/ss_iblt.bench.cpp ${SOURCES})
    #add_executable(psu_bench ${BENCH_SOURCE_PREFIX}/psu.bench.cpp ${SOURCES})
    #add_executable(ot_reduc ${BENCH_SOURCE_PREFIX}/ot_reduc.bench.cpp ${SOURCES})    
    #add_executable(simd_bench ${BENCH_SOURCE_PREFIX}/simd.bench.cpp ${SOURCES})
    #add_executable(bitvector_bench ${BENCH_SOURCE_PREFIX}/bitvector.bench.cpp ${SOURCES})
    #add_executable(multiaes_bench ${BENCH_SOURCE_PREFIX}/multiaes.bench.cpp ${SOURCES})
    #add_executable(preprocessing_bench ${BENCH_SOURCE_PREFIX}/preprocessing.bench.cpp ${SOURCES})
    #add_executable(iblt_h5_bench ${BENCH_SOURCE_PREFIX}/iblt_h5.bench.cpp ${SOURCES})

    foreach(target ${ALL_BENCHS})
        set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
        target_compile_features(${target} PUBLIC cxx_std_20)
        target_compile_options(${target} PRIVATE ${DEFAULT_COMPILER_OPTIONS_AND_WARNINGS})
        target_link_libraries(${target} PRIVATE Catch2::Catch2WithMain oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
        target_include_directories(${target} PRIVATE ${GMP_INCLUDE_DIR})
        #target_compile_options(${target} PRIVATE ${GMP_CFLAGS_OTHER})

        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()

if(BUILD_PROFILING_EXECUTABLES)
  set(ALL_PROFILING_EXECUTABLES
    profiling_psu_with_local_sockets
  )

  set (PROFILING_SOURCE_PREFIX ${CMAKE_SOURCE_DIR}/profiling)

  foreach(target ${ALL_PROFILING_EXECUTABLES})
      add_executable(${target} ${PROFILING_SOURCE_PREFIX}/${target}.cpp ${SOURCES})
      target_link_libraries(${target} visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)
      set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endforeach()
endif()

add_executable(calc_fss_key_size ${CMAKE_SOURCE_DIR}/calc_fss_key_size.cpp ${SOURCES})
target_link_libraries(calc_fss_key_size oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

add_executable(calc_fpir_response_size ${CMAKE_SOURCE_DIR}/calc_fpir_response_size.cpp ${SOURCES})
target_link_libraries(calc_fpir_response_size oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

add_executable(lpfss_benchmark_main ${CMAKE_SOURCE_DIR}/lpfss_benchmark_main.cpp ${SOURCES})
target_link_libraries(lpfss_benchmark_main PRIVATE oc::cryptoTools ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

add_executable(est_iblt_fail_prob ${CMAKE_SOURCE_DIR}/est_iblt_fail_prob.cpp)
target_link_libraries(est_iblt_fail_prob oc::cryptoTools)

#add_executable(psu_main ${CMAKE_SOURCE_DIR}/psu_main.cpp ${SOURCES})
#target_link_libraries(psu_main visa::volePSI coproto::coproto xxhash unordered_dense::unordered_dense)

#target_link_libraries(opt_iblt_exp visa::volePSI)
#if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  #target_compile_definitions(opt_iblt_exp_h4 PRIVATE DEBUG_MODE)
  #target_compile_definitions(opt_iblt_exp_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(pround_exps_h5 PRIVATE DEBUG_MODE)
  #target_compile_definitions(trypeel_main PRIVATE DEBUG_MODE)
  #target_compile_definitions(main_iblt_h5 PRIVATE DEBUG_MODE)
#endif()