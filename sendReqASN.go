package main

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
)

type AS_REQ_STRUCT struct {
	PVNO  asn_pvno `asn1:"tag:1,implicit,optional"`
	MSG_TYPE asn_msg_type `asn1:"tag:2,implicit,optional"`
	PADATA asn_padata `asn1:"tag:3,implicit"`
	REQ_BODY []asn_req_body `asn1:"tag:4,implicit"`
}

type asn_pvno struct {
	Item int
}
type asn_msg_type struct {
	Item int
}
type asn_padata struct {
	Items []asn_pa_data
}
type asn_pa_data struct {
	Padatatype asn_padatatype `asn1:"tag:1,implicit,optional"`
	Padatavalue asn_padatavalue `asn1:"tag:2,implicit,optional"`
}
type asn_padatatype struct {
	Item int
}
type asn_padatavalue struct {
	Item []byte
}
type asn_req_body struct {
	Item0 asn_kdc_options `asn1:"tag:0,implicit,optional"`
	Item1 []asn_cname `asn1:"tag:1,implicit,optional"`
	Item2 asn_realm `asn1:"tag:2,implicit,optional"`
	Item3 []asn_sname `asn1:"tag:3,implicit,optional"`
	Item5 asn_till `asn1:"tag:5,implicit,optional"`
	Item6 asn_rtime `asn1:"tag:6,implicit,optional"`
	Item7 asn_nonce `asn1:"tag:7,implicit,optional"`
	Item8 []asn_etype `asn1:"tag:8,implicit,optional"`
	Item9 asn_addresses `asn1:"tag:9,implicit,optional"`
}
type asn_kdc_options struct {
	Item asn1.BitString
}
type asn_cname struct {
	Item0 asn_name_type `asn1:"tag:0,implicit,optional"`
	Item1 []asn_cname_string `asn1:"tag:1,implicit,optional"`
}
type asn_name_type struct {
	Item int
}
type asn_cname_string struct {
	Item asn1.RawValue
}
type asn_realm struct {
	Item asn1.RawValue

}
type asn_sname struct {
	Item0 asn_name_type `asn1:"tag:0,implicit,optional"`
	Item1 asn_sname_string `asn1:"tag:1,implicit,optional"`
}
type asn_sname_string struct {
	Items []asn1.RawValue
}
type asn_till struct {
	Item asn1.RawValue
}
type asn_rtime struct {
	Item asn1.RawValue
}
type asn_nonce struct {
	Item int
}
type asn_etype struct {
	Item0 int
	Item1 int
	Item2 int
	Item3 int
	Item4 int
	Item5 int
}
type asn_addresses struct {
	Items []asn_hostaddress
}
type asn_hostaddress struct {
	Item0 asn_addr_type `asn1:"tag:0,implicit,optional"`
	Item1 asn_netbios_name `asn1:"tag:1,implicit,optional"`
}
type asn_addr_type struct {
	Item int
}
type asn_netbios_name struct {
	Item []byte
}

func sendReqASN(connect net.Conn,account string,domain string,machine string) {
	var as_req AS_REQ_STRUCT
	as_req.PVNO = asn_pvno{5}
	as_req.MSG_TYPE = asn_msg_type{10}
	padatatype := asn_padatatype{128}
	raw_padatavalue := "3005A0030101FF"
	data_padatavalue, _ := hex.DecodeString(raw_padatavalue)
	padatavalue := asn_padatavalue{data_padatavalue}
	temp := make([]asn_pa_data,1)
	as_req.PADATA.Items = temp
	as_req.PADATA.Items[0].Padatatype = padatatype
	as_req.PADATA.Items[0].Padatavalue = padatavalue

	raw_kdcoptions := "40810010"
	data_kdcoptions, _ := hex.DecodeString(raw_kdcoptions)

	temp2 := make([]asn_req_body,1)
	as_req.REQ_BODY = temp2
	as_req.REQ_BODY[0].Item0.Item = asn1.BitString{
		Bytes:     data_kdcoptions,
		BitLength: 32,
	}

	temp3 := make([]asn_cname,1)
	temp3[0].Item0 = asn_name_type{1}
	temp4 := make([]asn_cname_string,1)
	temp4[0].Item = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(account)}
	//temp4[0].Item = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("user")}
	temp3[0].Item1 = temp4
	as_req.REQ_BODY[0].Item1 = temp3
	as_req.REQ_BODY[0].Item2 = asn_realm{Item: asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(domain)}}
	//as_req.REQ_BODY[0].Item2 = asn_realm{Item: asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("TEST")}}

	temp5 := make([]asn_sname,1)
	temp5[0].Item0 = asn_name_type{2}
	var temp6 asn_sname_string
	temp6.Items = make([]asn1.RawValue,2)
	temp6.Items[0] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("krbtgt")}
	temp6.Items[1] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte(domain)}
	//temp6.Items[1] = asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("TEST")}
	temp5[0].Item1 = temp6
	as_req.REQ_BODY[0].Item3 = temp5


	tilldate := "20370913024805Z"
	rtimedate := "20370913024805Z"
	as_req.REQ_BODY[0].Item5 = asn_till{Item: asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(tilldate)}}
	as_req.REQ_BODY[0].Item6 = asn_rtime{Item: asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(rtimedate)}}
	as_req.REQ_BODY[0].Item7 = asn_nonce{183454254}

	temp7 := make([]asn_etype,1)
	temp7[0].Item0 = 18
	temp7[0].Item1 = 17
	temp7[0].Item2 = 23
	temp7[0].Item3 = 24
	temp7[0].Item4 = -135
	temp7[0].Item5 = 3
	as_req.REQ_BODY[0].Item8 = temp7

	temp8 := asn_addresses{}
	temp9 := make([]asn_hostaddress,1)
	temp9[0].Item0 = asn_addr_type{20}

	netBiosName := machine
	//netBiosName := "CLIENT1"
	netBiosNameLen := len(netBiosName)
	//fmt.Println(netBiosNameLen)
	padding := 16-netBiosNameLen
	for i:=0;i<padding;i++ {
		netBiosName = netBiosName+" " // Padding might be different https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
	}

	temp9[0].Item1 = asn_netbios_name{[]byte(netBiosName)}

	temp8.Items = temp9
	as_req.REQ_BODY[0].Item9 = temp8


	//mdata, _ := asn1.Marshal(as_req)
	//mdata, err := asn1.MarshalWithParams(as_req_resp,"application,explicit,tag:30")
	mdata, _ := asn1.MarshalWithParams(as_req,"application,explicit,tag:10")

	str := hex.EncodeToString(mdata)
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
	//fmt.Println(h2)
	parseAsReqResp(h2[:n*2])
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
