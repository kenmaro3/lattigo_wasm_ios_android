package simple

import (
	"fmt"

	// "time"
	"encoding/base64"
	"encoding/json"

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

func Encode_ctxt(ctxt Ctxt) string {
	// jsonData_res, err := json.Marshal(ctxt)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	data, err := ctxt.Data.MarshalBinary()
	if err != nil {
		fmt.Println(err)
	}

	base64string_res := base64.StdEncoding.EncodeToString(data)

	return base64string_res
}

func Decode_ctxt(ctxt_base64_str string) Ctxt {
	ctxt_tmp := new(rlwe.Ciphertext)
	decodedCtxt, err := base64.StdEncoding.DecodeString(ctxt_base64_str)
	ctxt_tmp.UnmarshalBinary(decodedCtxt)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
	}

	res := Ctxt{
		Data: *ctxt_tmp,
	}
	// err = json.Unmarshal(decodedCtxt, &ctxt)
	// if err != nil {
	// 	fmt.Println("Error unmarshaling JSON:", err)
	// }

	return res

}

func Encode_key_pairs(key_pairs KeyPairs) string {
	jsonData_res, err := json.Marshal(key_pairs)
	if err != nil {
		fmt.Println(err)
	}
	base64string_res := base64.StdEncoding.EncodeToString(jsonData_res)
	return base64string_res
}

func Decode_key_pairs(key_pairs_base64_str string) KeyPairs {
	decodedBytes, err := base64.StdEncoding.DecodeString(key_pairs_base64_str)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
	}

	// Step 2: Unmarshal the decoded bytes into your struct
	var key_pairs KeyPairs
	err = json.Unmarshal(decodedBytes, &key_pairs)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
	}

	return key_pairs
}

func Encode_key_pairs_public(key_pairs KeyPairsPublic) string {
	jsonData_res, err := json.Marshal(key_pairs)
	if err != nil {
		fmt.Println(err)
	}
	base64string_res := base64.StdEncoding.EncodeToString(jsonData_res)
	return base64string_res
}

func Decode_key_pairs_public(key_pairs_base64_str string) KeyPairsPublic {
	decodedBytes, err := base64.StdEncoding.DecodeString(key_pairs_base64_str)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
	}

	// Step 2: Unmarshal the decoded bytes into your struct
	var key_pairs KeyPairsPublic
	err = json.Unmarshal(decodedBytes, &key_pairs)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
	}

	return key_pairs
}

func Encode_key_pairs_secret(key_pairs KeyPairsSecret) string {
	jsonData_res, err := json.Marshal(key_pairs)
	if err != nil {
		fmt.Println(err)
	}
	base64string_res := base64.StdEncoding.EncodeToString(jsonData_res)
	return base64string_res
}

func Decode_key_pairs_secret(key_pairs_base64_str string) KeyPairsSecret {
	decodedBytes, err := base64.StdEncoding.DecodeString(key_pairs_base64_str)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
	}

	// Step 2: Unmarshal the decoded bytes into your struct
	var key_pairs KeyPairsSecret
	err = json.Unmarshal(decodedBytes, &key_pairs)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
	}

	return key_pairs
}

func KeyGen() string {
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

	res := Encode_key_pairs(key_pairs)

	// res_public := Encode_key_pairs_public(key_pairs_public)
	// res_secret := Encode_key_pairs_secret(key_pairs_secret)

	// res := make([]string, 2)
	// res[0] = res_public
	// res[1] = res_secret
	fmt.Println("Done KeyGen!")

	return res
}

func KeyPairs_to_public_encode(key_pairs_base64_str string) string {
	fmt.Println("Start KeyPairs_to_public_encode!")
	tmp := Decode_key_pairs(key_pairs_base64_str)
	res := Encode_key_pairs_public(tmp.Public)
	fmt.Println("Done KeyPairs_to_public_encode!")
	return res
}

func KeyPairs_to_secret_encode(key_pairs_base64_str string) string {
	fmt.Println("Start KeyPairs_to_secret_encode!")
	tmp := Decode_key_pairs(key_pairs_base64_str)
	res := Encode_key_pairs_secret(tmp.Secret)
	fmt.Println("Done KeyPairs_to_secret_encode!")
	return res
}

func Encrypt(key_pairs_public_base64_str string) Ctxt {
	key_pairs_public := Decode_key_pairs_public((key_pairs_public_base64_str))

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

func EncryptEncode(key_pairs_public_base64_str string) string {
	fmt.Println("Start EncryptEncode!")
	ctxt := Encrypt(key_pairs_public_base64_str)

	res := Encode_ctxt(ctxt)

	fmt.Println("Done EncryptEncode!")

	return res

}

func Decrypt(ctxt Ctxt, key_pairs_secret_base64_str string) {
	key_pairs_secret := Decode_key_pairs_secret(key_pairs_secret_base64_str)

	encoder := ckks.NewEncoder(key_pairs_secret.Params)
	decryptor := ckks.NewDecryptor(key_pairs_secret.Params, &key_pairs_secret.Sk)

	dec_res := encoder.DecodeSlots(decryptor.DecryptNew(&ctxt.Data), key_pairs_secret.Params.LogSlots())
	fmt.Printf("\ndec ct1==================\n")
	for i := 0; i < 3; i++ {
		fmt.Printf("%d: %7.4f\n", i, dec_res[i])
	}
}

func DecodeDecrypt(ctxt_base64_str string, key_pairs_secret_base64_str string) string {
	fmt.Println("Start Decode Decrypt!")
	key_pairs_secret := Decode_key_pairs_secret(key_pairs_secret_base64_str)

	ctxt := Decode_ctxt(ctxt_base64_str)

	encoder := ckks.NewEncoder(key_pairs_secret.Params)
	decryptor := ckks.NewDecryptor(key_pairs_secret.Params, &key_pairs_secret.Sk)

	dec_res := encoder.DecodeSlots(decryptor.DecryptNew(&ctxt.Data), key_pairs_secret.Params.LogSlots())
	fmt.Printf("\ndec ct1==================\n")
	for i := 0; i < 3; i++ {
		fmt.Printf("%d: %7.4f\n", i, dec_res[i])
	}

	dec_res_str := fmt.Sprintf("%7.4f, %7.4f, %7.4f\n", dec_res[0], dec_res[1], dec_res[2])
	fmt.Println("Done Decode Decrypt!")
	return dec_res_str
}

func Multiply(value int32) int32 {
	fmt.Println(value)

	// if value < 0 || value > 10 {
	// 	return 0, fmt.Errorf("value out of range: must be within the range of 0 to 10")
	// }

	return value * 2
}
