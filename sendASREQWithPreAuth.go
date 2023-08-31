package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/md4"
	"log"
	//"crypto/rc4"
	"math/rand"
	"net"
	"time"
)

func FromASCIIString(in string) []byte {
	var u16 []byte
	for _, b := range []byte(in) {
		u16 = append(u16, b)
		u16 = append(u16, 0x00)
	}
	mdfour := md4.New()
	mdfour.Write(u16)
	return mdfour.Sum(nil)
}

func FromASCIIStringToHex(in string) string {
	b := FromASCIIString(in)
	return hex.EncodeToString(b)
}

type AS_REQ_STRUCT_FOR_ENCRYPTED_TIMESTAMP struct {
	TIMESTAMP []asn1.RawValue `asn1:"tag:0"`
}

type AS_REQ_STRUCT_WITH_PRE_AUTH struct {
	PVNO  asn_pvno_with_pre_auth `asn1:"tag:1,implicit,optional"`
	MSG_TYPE asn_msg_type_with_pre_auth `asn1:"tag:2,implicit,optional"`
	PADATA asn_padata_with_pre_auth `asn1:"tag:3,implicit"`
	REQ_BODY []asn_req_body_with_pre_auth `asn1:"tag:4,implicit"`
}

type asn_pvno_with_pre_auth struct {
	Item int
}
type asn_msg_type_with_pre_auth struct {
	Item int
}
type asn_padata_with_pre_auth struct {
	Items []asn_pa_data_with_pre_auth
}
type asn_pa_data_with_pre_auth struct {
	Padatatype int `asn1:"tag:1,explicit"`
	Padatavalue []byte `asn1:"tag:2,explicit"`
}

//type asn_padatavalue_with_pre_auth struct {
//	Item []byte
//}

type asn_padatavalue_with_pre_auth struct {
		Etype asn_padata_etype_with_pre_auth `asn1:"tag:0"`
		Cipher asn_padata_cipher_with_pre_auth `asn1:"tag:2"`
}
type asn_padata_etype_with_pre_auth struct {
	Item int `asn1:"tag:0"`
}
type asn_padata_cipher_with_pre_auth struct {
	Item []byte `asn1:"tag:2"`
}

type asn_req_body_with_pre_auth struct {
	Item0 asn_kdc_options_with_pre_auth `asn1:"tag:0,implicit,optional"`
	Item1 []asn_cname_with_pre_auth `asn1:"tag:1,implicit,optional"`
	Item2 asn_realm_with_pre_auth `asn1:"tag:2,implicit,optional"`
	Item3 []asn_sname_with_pre_auth `asn1:"tag:3,implicit,optional"`
	Item5 asn_till_with_pre_auth `asn1:"tag:5,implicit,optional"`
	Item6 asn_rtime_with_pre_auth `asn1:"tag:6,implicit,optional"`
	Item7 asn_nonce_with_pre_auth `asn1:"tag:7,implicit,optional"`
	Item8 []asn_etype_with_pre_auth `asn1:"tag:8,implicit,optional"`
	Item9 asn_addresses_with_pre_auth `asn1:"tag:9,implicit,optional"`
}
type asn_kdc_options_with_pre_auth struct {
	Item asn1.BitString
}
type asn_cname_with_pre_auth struct {
	Item0 asn_name_type_with_pre_auth `asn1:"tag:0,implicit,optional"`
	Item1 []asn_cname_string_with_pre_auth `asn1:"tag:1,implicit,optional"`
}
type asn_name_type_with_pre_auth struct {
	Item int
}
type asn_cname_string_with_pre_auth struct {
	Item asn1.RawValue
}
type asn_realm_with_pre_auth struct {
	Item asn1.RawValue
}
type asn_sname_with_pre_auth struct {
	Item0 asn_name_type_with_pre_auth `asn1:"tag:0,implicit,optional"`
	Item1 asn_sname_string_with_pre_auth `asn1:"tag:1,implicit,optional"`
}
type asn_sname_string_with_pre_auth struct {
	Items []asn1.RawValue
}
type asn_till_with_pre_auth struct {
	Item asn1.RawValue
}
type asn_rtime_with_pre_auth struct {
	Item asn1.RawValue
}
type asn_nonce_with_pre_auth struct {
	Item int
}
type asn_etype_with_pre_auth struct {
	Item0 int
	Item1 int
	Item2 int
	Item3 int
	Item4 int
	Item5 int
}
type asn_addresses_with_pre_auth struct {
	Items []asn_hostaddress_with_pre_auth
}
type asn_hostaddress_with_pre_auth struct {
	Item0 asn_addr_type_with_pre_auth `asn1:"tag:0,implicit,optional"`
	Item1 asn_netbios_name_with_pre_auth `asn1:"tag:1,implicit,optional"`
}
type asn_addr_type_with_pre_auth struct {
	Item int
}
type asn_netbios_name_with_pre_auth struct {
	Item []byte
}

type TEMP_STRUCT struct {
	ETYPE TEMP_STRUCT_ETYPE `asn1:"tag:0,implicit,optional"`
	CIPHER []byte `asn1:"tag:2,explicit,optional"`
}
type TEMP_STRUCT_ETYPE struct {
	Item int
}

type TEMP_STRUCTB struct {
	Item bool `asn1:"tag:0,explicit,optional"`
}
//type TEMP_STRUCT_CIPHER struct {
//	Item int
//}

func rc4Encrypt(encData []byte, key []byte) []byte {
	dst := make([]byte, len(encData))
	rc4cipher, err := rc4.NewCipher(key)

	if err != nil {
		fmt.Println(err)
	}

	rc4cipher.XORKeyStream(dst, encData)
	return dst
}

func ComputeHmacMD5(message []byte, secret []byte) []byte {
	h := hmac.New(md5.New, secret)
	h.Write(message)
	return h.Sum(nil)
}

func sendReqWithPreAuthASN(connect net.Conn,account string,domain string,machine string) {
	var as_req AS_REQ_STRUCT_WITH_PRE_AUTH
	as_req.PVNO = asn_pvno_with_pre_auth{5}
	as_req.MSG_TYPE = asn_msg_type_with_pre_auth{10}
	padatatype := 2

	var tempA TEMP_STRUCT
	tempA.ETYPE = TEMP_STRUCT_ETYPE{23}
	//tempA.CIPHER = TEMP_STRUCT_CIPHER{}

	currentTimestamp := time.Now().UTC().Format("20060102150405")
	currentTimestamp = currentTimestamp+"Z"

	fmt.Println(currentTimestamp)

	temp22 := make([]asn1.RawValue,1)
	currentTimestampForEncryption := AS_REQ_STRUCT_FOR_ENCRYPTED_TIMESTAMP{temp22}

	currentTimestampForEncryption.TIMESTAMP[0] = asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(currentTimestamp)}
	tt,_ := asn1.Marshal(currentTimestampForEncryption)

	//fmt.Println(tt)
	//fmt.Println(error)
	//fmt.Println(currentTimestampForEncryption)
	str1 := hex.EncodeToString(tt)
	//fmt.Println(str1)
	//str1 = "3013A011180F32303233303833313131343535335A" // HARDCODE
	//str1 = "301aa011180f32303233303833313134343033385aa10502030a5b43" // HARDCODE
	ntlm := "BF24F6D8D5983E17412275A09474B328"
	key, _ := hex.DecodeString(ntlm)
	dataToEncrypt, _ := hex.DecodeString(str1)
	confounder := make([]byte, 8)
	rand.Read(confounder)
	//confounder, _ = hex.DecodeString("b40c59e6d9e93bee")
	//fmt.Println("Confounder: ", hex.EncodeToString(confounder))
	cls_usage_str,_:= hex.DecodeString("01000000")
	ki := hmac.New(md5.New, key)
	ki.Write(cls_usage_str)
	//kiString := hex.EncodeToString(ki.Sum(nil))
	//fmt.Println("KI:",kiString)
	cksum := hmac.New(md5.New, ki.Sum(nil))
	payload := append(confounder,dataToEncrypt...)
	//fmt.Println("payload:",hex.EncodeToString(payload))
	cksum.Write(payload)
	cksumString := hex.EncodeToString(cksum.Sum(nil))
	//fmt.Println("cksum:",cksumString)
	ke := hmac.New(md5.New, ki.Sum(nil))
	ke.Write(cksum.Sum(nil))
	//keString := hex.EncodeToString(ke.Sum(nil))
	//fmt.Println("KE:",keString)

	c, err := rc4.NewCipher(ke.Sum(nil))
	if err != nil {
		log.Fatalln(err)
	}
	src := payload
	//fmt.Println("Plaintext: ", hex.EncodeToString(src))

	dst := make([]byte, len(src))
	c.XORKeyStream(dst, src)
	//fmt.Println("Ciphertext: ", hex.EncodeToString(dst))

	totalResult := cksumString+hex.EncodeToString(dst)
	fmt.Println(totalResult)

	//c, _ := rc4.NewCipher(key)
	////src := []byte(str1)
	//src, _ := hex.DecodeString(str1)
	//fmt.Println("Plaintext: ", src)
	//dst := make([]byte, len(src))
	//c.XORKeyStream(dst, src)
	//fmt.Println("Ciphertext: ", dst)
	//fmt.Println(hex.EncodeToString(dst))
	//
	//sig := hmac.New(sha256.New, key)
	//sig.Write(dst)
	//fmt.Println(hex.EncodeToString(sig.Sum(nil)))


	//raw_data := "67e4998d90b6cf761be64bb88075929f747a4d59a1b7c09164afe64b3c881954599ec263f30daf736f11ec5abddec4b2a720dd2fa701f29c" // cipher - encryptedTimestamp
	raw_data := totalResult
	data_data, _ := hex.DecodeString(raw_data)
	tempA.CIPHER = data_data
	mdata, _ := asn1.Marshal(tempA)


	temp := make([]asn_pa_data_with_pre_auth,2)
	as_req.PADATA.Items = temp
	as_req.PADATA.Items[0].Padatatype = padatatype
	as_req.PADATA.Items[0].Padatavalue = mdata


	padatatype2 := 128
	var tempB TEMP_STRUCTB
	tempB.Item = true
	//tempA.CIPHER = TEMP_STRUCT_CIPHER{}

	mdataB, _ := asn1.Marshal(tempB)
	as_req.PADATA.Items[1].Padatatype = padatatype2
	as_req.PADATA.Items[1].Padatavalue = mdataB

	raw_kdcoptions := "40810010"
	data_kdcoptions, _ := hex.DecodeString(raw_kdcoptions)

	temp2 := make([]asn_req_body_with_pre_auth,1)
	as_req.REQ_BODY = temp2
	as_req.REQ_BODY[0].Item0.Item = asn1.BitString{
		Bytes:     data_kdcoptions,
		BitLength: 32,
	}

	temp3 := make([]asn_cname_with_pre_auth,1)
	temp3[0].Item0 = asn_name_type_with_pre_auth{1}
	temp4 := make([]asn_cname_string_with_pre_auth,1)
	temp4[0].Item = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(account)}
	//temp4[0].Item = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("user")}
	temp3[0].Item1 = temp4
	as_req.REQ_BODY[0].Item1 = temp3
	as_req.REQ_BODY[0].Item2 = asn_realm_with_pre_auth{Item: asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(domain)}}
	//as_req.REQ_BODY[0].Item2 = asn_realm{Item: asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("TEST")}}

	temp5 := make([]asn_sname_with_pre_auth,1)
	temp5[0].Item0 = asn_name_type_with_pre_auth{2}
	var temp6 asn_sname_string_with_pre_auth
	temp6.Items = make([]asn1.RawValue,2)
	temp6.Items[0] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("krbtgt")}
	temp6.Items[1] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(domain)}
	//temp6.Items[1] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("TEST")}
	temp5[0].Item1 = temp6
	as_req.REQ_BODY[0].Item3 = temp5

	tilldate := "20370913024805Z"
	rtimedate := "20370913024805Z"
	as_req.REQ_BODY[0].Item5 = asn_till_with_pre_auth{Item: asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(tilldate)}}
	as_req.REQ_BODY[0].Item6 = asn_rtime_with_pre_auth{Item: asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(rtimedate)}}
	as_req.REQ_BODY[0].Item7 = asn_nonce_with_pre_auth{183454254}

	temp7 := make([]asn_etype_with_pre_auth,1)
	temp7[0].Item0 = 18
	temp7[0].Item1 = 17
	temp7[0].Item2 = 23
	temp7[0].Item3 = 24
	temp7[0].Item4 = -135
	temp7[0].Item5 = 3
	as_req.REQ_BODY[0].Item8 = temp7

	temp8 := asn_addresses_with_pre_auth{}
	temp9 := make([]asn_hostaddress_with_pre_auth,1)
	temp9[0].Item0 = asn_addr_type_with_pre_auth{20}

	netBiosName := machine
	//netBiosName := "CLIENT1"
	netBiosNameLen := len(netBiosName)
	//fmt.Println(netBiosNameLen)
	padding := 16-netBiosNameLen
	for i:=0;i<padding;i++ {
		netBiosName = netBiosName+" " // Padding might be different https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
	}

	temp9[0].Item1 = asn_netbios_name_with_pre_auth{[]byte(netBiosName)}

	temp8.Items = temp9
	as_req.REQ_BODY[0].Item9 = temp8


	//mdata, _ := asn1.Marshal(as_req)
	//mdata, err := asn1.MarshalWithParams(as_req_resp,"application,explicit,tag:30")
	mdata, _ = asn1.MarshalWithParams(as_req,"application,explicit,tag:10")

	str := hex.EncodeToString(mdata)
	fmt.Println(str)
	fmt.Println("")
	fmt.Println(str)
	//dataLen := uint32(len(str)/2)
	//h := fmt.Sprintf("%x", dataLen)
	//fmt.Println(dataLen,h)
	//appPadding := "6a81"+h
	//str = appPadding+str
	//fmt.Println(str)


	messageLen := uint32(len(str)/2)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, messageLen)
	//fmt.Println(bs)

	data,_ := hex.DecodeString(str)

	data = append(bs,data...)


	//fmt.Println(data)
	//fmt.Println(hex.EncodeToString(data))
	connect.Write(data)
	recvBuf := make([]byte, 1024)

	n, err := connect.Read(recvBuf[:]) // recv data
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Println("read timeout:", err)
		} else {
			log.Println("read error:", err)
		}
	}
	//fmt.Println(n)
	//fmt.Println(recvBuf)
	h2 := fmt.Sprintf("%x", recvBuf)
	fmt.Println(h2)
	parseAsReqResp(h2[:n*2])

	fmt.Println(FromASCIIStringToHex("123"))
}


