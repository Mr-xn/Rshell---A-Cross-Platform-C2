package neoreg

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	cmdData    = 1
	cmdCommand = 2
	cmdMark    = 3
	cmdStatus  = 4
	cmdError   = 5
	cmdIP      = 6
	cmdPort    = 7
	blvHeadLen = 9
)

var (
	DefaultTimeout        = 5 * time.Second
	DefaultMaxRetry       = 10
	DefaultInterval       = 100 * time.Millisecond
	DefaultReadBufferSize = 32 * 1024
	saltPrefix            = []byte("11f271c6lm0e9ypkptad1uv6e1ut1fu0pt4xillz1w9bbs2gegbv89z9gca9d6tbk025uvgjfr331o0szln")
	BASE64CHARS           = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var defaultHeaders = map[string]string{
	"Accept-Encoding": "gzip, deflate",
	"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Content-Type":    "application/octet-stream",
}

// NeoregClient 实现了Client接口
type NeoregClient struct {
	Proxy  *url.URL
	Conf   *NeoregConf
	Client *http.Client
}

// NeoregConf 配置结构
type NeoregConf struct {
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
	Protocol string // http/https
	Uid      string

	EncodeMap map[byte]byte
	DecodeMap map[byte]byte

	Key  string
	Rand *NeoregRand

	blvOffset int32 // 对应Python中的BLV_L_OFFSET

	Timeout        time.Duration
	MaxRetry       int
	Interval       time.Duration
	ReadBufferSize int
}

func NewConf(uid string, key string) (*NeoregConf, error) {

	mt := NewNeoregRand(key)
	encodeMap, decodeMap, blvOffset := generateMaps(mt)

	conf := &NeoregConf{
		Dial:      (&net.Dialer{}).DialContext,
		Uid:       uid,
		EncodeMap: encodeMap,
		DecodeMap: decodeMap,
		Key:       key,
		Rand:      mt,
		blvOffset: blvOffset,

		Timeout:        DefaultTimeout,
		MaxRetry:       DefaultMaxRetry,
		Interval:       DefaultInterval,
		ReadBufferSize: DefaultReadBufferSize,
	}

	return conf, nil
}
