package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Tx is the transactional information between two parties.
type Tx struct {
	FromID string `json:"from"`
	ToID   string `json:"to"`
	Value  uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {

	tx := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Aaron",
		Value:  1000,
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to load marshall, %w", err)
	}

	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key, %w", err)
	}

	v := crypto.Keccak256(data)

	sig, err := crypto.Sign(v, privateKey)
	if err != nil {
		return fmt.Errorf("unable to load sign, %w", err)
	}

	fmt.Println(hexutil.Encode(sig))

	// ================================================================

	publicKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to load pub, %w", err)
	}

	fmt.Println(crypto.PubkeyToAddress(*publicKey).String())

	// ================================================================

	tx = Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Another",
		Value:  1000,
	}

	data, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to load marshall, %w", err)
	}

	privateKey, err = crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key, %w", err)
	}

	v = crypto.Keccak256(data)

	sig, err = crypto.Sign(v, privateKey)
	if err != nil {
		return fmt.Errorf("unable to load sign, %w", err)
	}

	fmt.Println(hexutil.Encode(sig))

	// ================================================================

	publicKey, err = crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to load pub, %w", err)
	}

	fmt.Println(crypto.PubkeyToAddress(*publicKey).String())

	return nil
}
