package neoreg

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"sort"
)

func generateMaps(rng *NeoregRand) (map[byte]byte, map[byte]byte, int32) {
	blvOffset := int32(rng.mt.GetRandBits(31).Int64())

	base64Chars := []rune(BASE64CHARS)
	var mBase64Chars []rune
	mBase64Chars = make([]rune, len(base64Chars))
	copy(mBase64Chars, base64Chars)
	rng.Base64Chars(mBase64Chars)

	encodeMap := make(map[byte]byte)
	decodeMap := make(map[byte]byte)

	for i := 0; i < len(base64Chars); i++ {
		encodeMap[byte(base64Chars[i])] = byte(mBase64Chars[i])
		decodeMap[byte(mBase64Chars[i])] = byte(base64Chars[i])
	}

	return encodeMap, decodeMap, blvOffset
}

func base64encode(rawdata []byte, encodeMap map[byte]byte) []byte {
	data := []byte(base64.StdEncoding.EncodeToString(rawdata))
	size := len(data)
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		n := encodeMap[data[i]]
		if n == 0 {
			out[i] = data[i]
		} else {
			out[i] = n
		}
	}
	return out
}

func base64decode(data []byte, decodeMap map[byte]byte) ([]byte, error) {
	size := len(data)
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		n := decodeMap[data[i]]
		if n == 0 {
			out[i] = data[i]
		} else {
			out[i] = n
		}
	}
	return base64.StdEncoding.DecodeString(string(out))
}

func blvEncode(info map[int][]byte, offset int32) []byte {
	info[0] = randbyte()
	info[39] = randbyte()

	data := bytes.NewBuffer(nil)

	keys := make([]int, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, b := range keys {
		v := info[b]
		l := len(v)

		binary.Write(data, binary.BigEndian, byte(b))
		binary.Write(data, binary.BigEndian, int32(l)+offset)
		data.Write(v)
	}

	return data.Bytes()
}

func blvDecode(data []byte, offset int32) map[int][]byte {
	info := make(map[int][]byte)
	in := bytes.NewReader(data)

	for {
		var bByte byte
		var lInt32 int32

		if err := binary.Read(in, binary.BigEndian, &bByte); err != nil {
			break
		}
		if err := binary.Read(in, binary.BigEndian, &lInt32); err != nil {
			return nil
		}

		b := int(bByte)
		l := int(lInt32 - offset)

		if l < 0 {
			return nil
		}

		v := make([]byte, l)
		if _, err := io.ReadFull(in, v); err != nil {
			return nil
		}

		if b > 0 && b < blvHeadLen {
			info[b] = v
		}
	}

	return info
}

func encodeBody(info map[int][]byte, conf *NeoregConf) []byte {
	data := blvEncode(info, conf.blvOffset)
	return base64encode(data, conf.EncodeMap)
}

func decodeBody(data []byte, conf *NeoregConf) map[int][]byte {
	rawdata, _ := base64decode(data, conf.DecodeMap)
	return blvDecode(rawdata, conf.blvOffset)
}
