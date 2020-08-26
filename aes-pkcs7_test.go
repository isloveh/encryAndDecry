package encryAndDecry

import (
	"fmt"
	"testing"
)

func TestPKCS7_AesDeCrypt(t *testing.T) {
	p := &PKCS7{
		Secret: []byte("1234454512344545"),
	}
	a, err := p.Encryption([]byte("1233dfasdfasdfasdfasdfasdfasdfasdf"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(a)
}

func TestPKCS7_AesEcrypt(t *testing.T) {
	p := &PKCS7{
		Secret: []byte("1234454512344545"),
	}
	a, err := p.Encryption([]byte("1233dfasdfasdfasdfasdfasdfasdfasdf"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Decrypt(a)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(b)
}
