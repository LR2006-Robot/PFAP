include_directories(
  .
  poseidon
  mint
  smt
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

################
# 生成链接库
################
# Global Poseidon sparse-Merkle-tree (state Merkle Tree) shared library.
add_library(
  zk_smt
  SHARED
  smt/smtcgo.cpp
)

add_library(
  zk_mint
  SHARED
  mint/mintcgo.cpp
)
target_link_libraries(zk_mint zk_smt)

add_library(
  zk_redeem
  SHARED
  redeem/redeemcgo.cpp
)
target_link_libraries(zk_redeem zk_smt)

add_library(
  zk_transfer
  SHARED
  transfer/transfercgo.cpp
)
target_link_libraries(zk_transfer zk_smt)

add_library(
  zk_createaccount
  SHARED
  createAccount/createaccountcgo.cpp
)

###############################
# 生成各个gadget的所需的pk，vk
###############################
add_executable(
  mint_key
  mint/getpvk.cpp
)
target_link_libraries(mint_key snark)
target_include_directories(mint_key PUBLIC ${DEPENDS_DIR}/libsnark ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_executable(
  redeem_key
  redeem/getpvk.cpp
)
target_link_libraries(redeem_key snark)
target_include_directories(redeem_key PUBLIC ${DEPENDS_DIR}/libsnark ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_executable(
  transfer_key
  transfer/getpvk.cpp
)
target_link_libraries(transfer_key snark)
target_include_directories(transfer_key PUBLIC ${DEPENDS_DIR}/libsnark ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_executable(
  createaccount_key
  createAccount/getpvk.cpp
)
target_link_libraries(createaccount_key snark)
target_include_directories(createaccount_key PUBLIC ${DEPENDS_DIR}/libsnark ${DEPENDS_DIR}/libsnark/depends/libfqfft)

##########################################
# test setup, genProof and verProof
##########################################
add_executable(
  createaccount
  createAccount/main.cpp
)
target_link_libraries(createaccount snark)
target_include_directories(createaccount PUBLIC ${DEPENDS_DIR}/libsnark ${DEPENDS_DIR}/libsnark/depends/libfqfft)
