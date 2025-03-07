#!/bin/bash
cd sdk-repo
go run ./cmd/sequence/ server --debug --port 9999 &
timeout 30 bash -c 'while ! curl -s -o /dev/null http://localhost:9999/rpc; do sleep 1; done'
cd ..
forge test
