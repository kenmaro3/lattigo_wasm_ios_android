package main

import (
	// "encoding/base64"
	// "encoding/json"
	"fmt"
	"labs/direct"
	"time"

	"github.com/tuneinsight/lattigo/v4/ckks"
	// "time"
	// "github.com/tuneinsight/lattigo/v4/ckks"
	// "github.com/tuneinsight/lattigo/v4/rlwe"
)

func test() {
	fmt.Println("Hello, Go Assembly!")
	now := time.Now()

	// ckksParamsResidualLit := ckks.ParametersLiteral{
	// 	LogN:     13,                    // Log2 of the ringdegree
	// 	LogSlots: 12,                    // Log2 of the number of slots
	// 	LogQ:     []int{55, 40}, // Log2 of the ciphertext prime moduli
	// 	LogP:     []int{61, 61, 61, 61}, // Log2 of the key-switch auxiliary prime moduli
	// 	// LogScale: 40,                    // Log2 of the scale
	// 	H: 192, // Hamming weight of the secret
	// }
	// paramsN12, err := ckks.NewParametersFromLiteral(
	// 	ckks.ParametersLiteral{
	// 		LogN:         14,
	// 		LogQ:         []int{55, 40, 40, 40, 40, 40, 40, 40},
	// 		LogP:         []int{45, 45},
	// 		LogSlots:     13,
	// 		DefaultScale: 40,
	// 	})
	var err error
	var paramsN12 ckks.Parameters

	// Scheme params are taken directly from the proposed defaults
	paramsN12, err = ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}
	// This generate ckks.Parameters, with the NTT tables and other pre-computations from the ckks.ParametersLiteral (which is only a template).
	// paramsN12, err := ckks.NewParametersFromLiteral(ckksParamsResidualLit)
	// if err != nil {
	// 	panic(err)
	// }

	// Scheme context and keys
	kgenN12 := ckks.NewKeyGenerator(paramsN12)
	skN12, _ := kgenN12.GenKeyPair()
	//skN12 := kgenN12.GenSecretKey()
	encoderN12 := ckks.NewEncoder(paramsN12)
	encryptorN12 := ckks.NewEncryptor(paramsN12, skN12)
	decryptorN12 := ckks.NewDecryptor(paramsN12, skN12)
	fmt.Printf("Gen sk/pk Done(%s)\n", time.Since(now))
	now = time.Now()

	// Rotation Keys
	rotations := []int{}
	for i := 1; i < paramsN12.N(); i <<= 1 {
		rotations = append(rotations, i)
	}

	_ = kgenN12.GenRotationKeysForRotations(rotations, true, skN12)

	// Relinearization Key
	_ = kgenN12.GenRelinearizationKey(skN12, 1)
	fmt.Printf("Gen RelinKey Done(%s)\n", time.Since(now))
	now = time.Now()

	// // CKKS Evaluator
	// evalCKKS := ckks.NewEvaluator(paramsN12, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey})

	// Preparation
	// will calculate dot([1,2,3], [1,2,3]) = 1*1 + 2*2 + 3*3 = 14
	vec1 := make([]float64, paramsN12.Slots())
	vec1[0] = 1.0
	vec1[1] = 2.0
	vec1[2] = 3.0

	// Encodeing for CKKS
	pt1 := ckks.NewPlaintext(paramsN12, paramsN12.MaxLevel())
	pt2 := ckks.NewPlaintext(paramsN12, paramsN12.MaxLevel())
	encoderN12.EncodeSlots(vec1, pt1, paramsN12.LogSlots())
	encoderN12.EncodeSlots(vec1, pt2, paramsN12.LogSlots())

	// Encryption
	ct1 := encryptorN12.EncryptNew(pt1)
	fmt.Printf("Enc Done (%s)\n", time.Since(now))

	dec_res := encoderN12.DecodeSlots(decryptorN12.DecryptNew(ct1), paramsN12.LogSlots())
	fmt.Printf("\ndec ct1==================\n")
	for i := 0; i < 3; i++ {
		fmt.Printf("%d: %7.4f -> %7.4f\n", i, vec1[i], real(dec_res[i]))
	}
	fmt.Printf("done")
}

func main() {
	// key_pairs_base64_str := simple.KeyGen()
	// var key_pairs_public_base64_str = simple.KeyPairs_to_public_encode(key_pairs_base64_str)
	// var key_pairs_secret_base64_str = simple.KeyPairs_to_secret_encode(key_pairs_base64_str)
	// ctxt_base64_str := simple.EncryptEncode(key_pairs_public_base64_str)
	// //sk := simple.Decode_key_pairs_secret(key_pairs_secret_base64_str)
	// dec_str := simple.DecodeDecrypt(ctxt_base64_str, key_pairs_secret_base64_str)
	// fmt.Printf(dec_str)

	key_pairs := direct.KeyGen()
	ctxt := direct.Encrypt(key_pairs.Public)
	dec_str := direct.Decrypt(ctxt, key_pairs.Secret)
	fmt.Printf(dec_str)

}
