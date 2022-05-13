package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

func createMnemonic() (string, error) {
	// Entropy 生成, 注意传入值y=32*x,并且128<=y<=256
	var err error
	b, err := bip39.NewEntropy(128)
	if err != nil {
		fmt.Println("failed creating entropy")
		return "", err
	}

	// 生成助记词
	nm, err := bip39.NewMnemonic(b)
	if err != nil {
		fmt.Println("failed creating mnemonic")
		return "", err
	}
	return nm, nil
}

func DerivePricateKey(path accounts.DerivationPath, masterKey *hdkeychain.ExtendedKey) (*ecdsa.PrivateKey, error) {
	var err error
	key := masterKey
	for _, k := range path {
		key, err = key.Child(k)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	pricateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return pricateKeyECDSA, nil
}

func DerivePublicKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to derive public key")
	}

	return publicKeyECDSA, nil
}

func DeriveAddressFromMnemonic() {
	// 1. 推导路径
	path, err := accounts.ParseDerivationPath("m/44'/60'/0'/0/1")
	if err != nil {
		panic(err)
	}

	// 2. 生成seed
	nm, err := createMnemonic()
	if err != nil {
		panic(err)
	}

	seed, err := bip39.NewSeedWithErrorChecking(nm, "")
	if err != nil {
		panic(err)
	}

	// 3. 生成masterKey
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println("Failed to NewMaster: ", err)
		return
	}

	// 4. 推导私钥
	privateKey, err := DerivePricateKey(path, masterKey)
	if err != nil {
		panic(err)
	}

	// 5. 推导公钥
	publicKey, err := DerivePublicKey(privateKey)
	if err != nil {
		panic(err)
	}

	// 6. 利用公钥推导钱包地址
	address := crypto.PubkeyToAddress(*publicKey)

	fmt.Println(address.Hex())


}

func main() {
	DeriveAddressFromMnemonic()
}
