package direct

import (
	"fmt"

	// "time"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type KeyPairsPublic struct {
	Params ckks.Parameters `json:"params"`
	Pk     rlwe.PublicKey  `json:"pk"`
	// Encoder   ckks.Encoder    `json:"encoder"`
	// Encryptor rlwe.Encryptor  `json:"encryptor"`
}

type KeyPairsSecret struct {
	Params ckks.Parameters `json:"params"`
	Sk     rlwe.SecretKey  `json:"sk"`
	// Decryptor rlwe.Decryptor  `json:"decryptor"`
	// Encoder   ckks.Encoder    `json:"encoder"`
}

type KeyPairs struct {
	Public KeyPairsPublic `json:"public"`
	Secret KeyPairsSecret `json:"secret"`
}

type Ctxt struct {
	Data rlwe.Ciphertext `json:"data"`
}

func KeyGen() KeyPairs {
	fmt.Println("Start KeyGen!")

	var err error
	var paramsN12 ckks.Parameters

	// Scheme params are taken directly from the proposed defaults
	paramsN12, err = ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}

	// Scheme context and keys
	kgenN12 := ckks.NewKeyGenerator(paramsN12)
	skN12, pkN12 := kgenN12.GenKeyPair()
	//skN12 := kgenN12.GenSecretKey()
	// encoder := ckks.NewEncoder(paramsN12)
	// encryptor := ckks.NewEncryptor(paramsN12, skN12)
	// decryptor := ckks.NewDecryptor(paramsN12, skN12)
	// fmt.Printf("Gen sk/pk Done(%s)\n", time.Since(now))
	// now = time.Now()

	var key_pairs_public = KeyPairsPublic{
		Params: paramsN12,
		Pk:     *pkN12,
		// Encoder:   encoder,
		// Encryptor: encryptor,
	}

	var key_pairs_secret = KeyPairsSecret{
		Params: paramsN12,
		Sk:     *skN12,
		// Decryptor: decryptor,
		// Encoder:   encoder,
	}

	key_pairs := KeyPairs{
		Public: key_pairs_public,
		Secret: key_pairs_secret,
	}

	fmt.Println("Done KeyGen!")

	return key_pairs
}

func KeyPairs_to_public(key_pairs KeyPairs) KeyPairsPublic {
	return key_pairs.Public
}

func KeyPairs_to_secret(key_pairs KeyPairs) KeyPairsSecret {
	return key_pairs.Secret
}

func Encrypt(key_pairs_public KeyPairsPublic) Ctxt {
	ptxt := make([]float64, key_pairs_public.Params.Slots())
	ptxt[0] = 1.0
	ptxt[1] = 2.0
	ptxt[2] = 3.0
	pt1 := ckks.NewPlaintext(key_pairs_public.Params, key_pairs_public.Params.MaxLevel())

	encoder := ckks.NewEncoder(key_pairs_public.Params)
	encryptor := ckks.NewEncryptor(key_pairs_public.Params, key_pairs_public.Pk)

	encoder.EncodeSlots(ptxt, pt1, key_pairs_public.Params.LogSlots())

	// Encryption
	ct1 := encryptor.EncryptNew(pt1)

	var ctxt = Ctxt{
		Data: *ct1,
	}

	return ctxt

}

func Decrypt(ctxt Ctxt, key_pairs_secret KeyPairsSecret) string {

	encoder := ckks.NewEncoder(key_pairs_secret.Params)
	decryptor := ckks.NewDecryptor(key_pairs_secret.Params, &key_pairs_secret.Sk)

	dec_res := encoder.DecodeSlots(decryptor.DecryptNew(&ctxt.Data), key_pairs_secret.Params.LogSlots())
	fmt.Printf("\ndec ct1==================\n")
	for i := 0; i < 3; i++ {
		fmt.Printf("%d: %7.4f\n", i, dec_res[i])
	}
	dec_res_str := fmt.Sprintf("%7.4f, %7.4f, %7.4f\n", dec_res[0], dec_res[1], dec_res[2])
	fmt.Println("Done Decrypt!")
	return dec_res_str
}

func Multiply(value int32) int32 {
	fmt.Println(value)

	// if value < 0 || value > 10 {
	// 	return 0, fmt.Errorf("value out of range: must be within the range of 0 to 10")
	// }

	return value * 2
}
