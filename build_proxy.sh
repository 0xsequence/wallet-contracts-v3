#!/bin/bash
SOL_VERSION="^0.8.0"
HUFF_FILE="./src/Wallet.huff"
SOL_OUT="./src/Wallet.sol"
BYTECODE=$(huff -z -e paris "$HUFF_FILE" CONSTRUCTOR | sed 's/^0x//')
HUFF_RAW=$(cat "$HUFF_FILE")
cat > "$SOL_OUT" <<EOF
// SPDX-License-Identifier: Apache-2.0
pragma solidity $SOL_VERSION;

/*
$HUFF_RAW
*/

library Wallet {

  bytes internal constant creationCode =
    hex"$BYTECODE";

}
EOF
