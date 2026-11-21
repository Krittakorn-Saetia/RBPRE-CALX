// Entry point for the RBPRE-CALX chaincode as a ccaas (chaincode-as-a-service)
// container. The peer connects to us over gRPC at CHAINCODE_SERVER_ADDRESS.
package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	contract := &RBPREContract{}
	contract.TransactionContextHandler = new(RBContext)
	contract.AfterTransaction = emitChanges
	cc, err := contractapi.NewChaincode(contract)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create chaincode: %v\n", err)
		os.Exit(1)
	}

	ccid := os.Getenv("CHAINCODE_ID")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")
	if ccid == "" || address == "" {
		fmt.Fprintf(os.Stderr, "CHAINCODE_ID and CHAINCODE_SERVER_ADDRESS must be set\n")
		os.Exit(1)
	}

	server := &shim.ChaincodeServer{
		CCID:    ccid,
		Address: address,
		CC:      cc,
		TLSProps: shim.TLSProperties{
			Disabled: true, // local dev only; production would set certs
		},
	}

	fmt.Printf("RBPRE-CALX chaincode listening on %s (CCID=%s)\n", address, ccid)
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "chaincode server: %v\n", err)
		os.Exit(1)
	}
}
