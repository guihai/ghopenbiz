package cmbc

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"math/big"
)

// 招商使用sm4 加密 解密工具
type SMTool struct {
}

//  签名
func (s *SMTool) SignString(uid, prikey, data string) string {
	if len(uid) != 16 {
		return ""
	}

	b64, _ := base64.StdEncoding.DecodeString(prikey)

	bhex := hex.EncodeToString(b64)

	priKey, err := x509.ReadPrivateKeyFromHex(bhex)
	if err != nil {

		return ""

	}

	ri, si, err := sm2.Sm2Sign(priKey, []byte(data), []byte(uid), nil)

	if err != nil {

		return ""

	}

	var buffer bytes.Buffer

	buffer.Write(ri.Bytes())

	buffer.Write(si.Bytes())

	signature := base64.StdEncoding.EncodeToString(buffer.Bytes())

	return signature
}

//验签
func (s *SMTool) VerifyString(uid, pubKey, data, sign string) bool {

	if len(uid) != 16 {
		return false
	}

	b64, _ := base64.StdEncoding.DecodeString(pubKey)

	bhex := hex.EncodeToString(b64)

	pub, err := x509.ReadPublicKeyFromHex(bhex)
	if err != nil {

		return false
	}

	dst, _ := base64.StdEncoding.DecodeString(sign)

	llen := len(dst)
	ri := new(big.Int).SetBytes(dst[:(llen / 2)])
	si := new(big.Int).SetBytes(dst[(llen / 2):])

	return sm2.Sm2Verify(pub, []byte(data), []byte(uid), ri, si)

}

// 加密
func (s *SMTool) EncryptByString(uid, uKey string, data []byte) (string, error) {

	block, err := sm4.NewCipher([]byte(uKey))
	if err != nil {
		return "", err
	}
	paddData := paddingLastGroup(data, block.BlockSize())
	iv := []byte(uid)
	if len(iv) != 16 {
		return "", errors.New("uid 必须 16 位")
	}
	blokMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(paddData))
	blokMode.CryptBlocks(cipherText, paddData)

	return base64.StdEncoding.EncodeToString(cipherText), nil

}

// 解密
func (s *SMTool) DecryptByString(uid, uKey, data string) ([]byte, error) {

	data64, _ := base64.StdEncoding.DecodeString(data)

	block, err := sm4.NewCipher([]byte(uKey))
	if err != nil {
		return nil, err
	}
	iv := []byte(uid)
	if len(iv) != 16 {
		return nil, errors.New("uid 必须 16 位")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(data64, data64)
	plainText := unpaddingLastGroup(data64)
	return plainText, nil
}

//明文数据填充
func paddingLastGroup(plainText []byte, blockSize int) []byte {

	padNum := blockSize - len(plainText)%blockSize

	char := []byte{byte(padNum)}

	newPlain := bytes.Repeat(char, padNum)

	newText := append(plainText, newPlain...)

	return newText
}

func unpaddingLastGroup(plainText []byte) []byte {

	length := len(plainText)
	lastChar := plainText[length-1]

	number := int(lastChar)
	return plainText[:length-number]
}

