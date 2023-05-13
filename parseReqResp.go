package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

type AS_REQ_RESP_STRUCT struct {
	PVNO  asn_resp_pvno `asn1:"tag:0,implicit,optional"`
	MSG_TYPE asn_resp_msg_type `asn1:"tag:1,implicit,optional"`
	STIME asn_resp_stime `asn1:"tag:4,implicit"`
	SUSEC  asn_resp_susec `asn1:"tag:5,implicit,optional"`
	ERROR_CODE  asn_resp_error_code `asn1:"tag:6,implicit,optional"`
	REALM  asn_resp_realm `asn1:"tag:9,implicit,optional"`
	SNAME []asn_resp_sname `asn1:"tag:10,implicit"`
	E_DATA asn_resp_e_data `asn1:"tag:12,implicit,optional"`
}

type asn_resp_pvno struct {
	Item int
}
type asn_resp_msg_type struct {
	Item int
}
type asn_resp_stime struct {
	Item asn1.RawValue
}
type asn_resp_susec struct {
	Item int
}
type asn_resp_error_code struct {
	Item int
}
type asn_resp_realm struct {
	Item asn1.RawValue
}
type asn_resp_sname struct {
	Item0 asn_name_type `asn1:"tag:0,implicit,optional"`
	Item1 asn_resp_sname_strings `asn1:"tag:1,implicit,optional"`
}
type asn_resp_name_type struct {
	Item int
}
type asn_resp_sname_strings struct {
	Items []asn1.RawValue
}
type asn_resp_e_data struct {
	Item []byte
}

func parseAsReqResp(resp string) {
	resp = resp[8:]
	data, _ := hex.DecodeString(resp)
	var n AS_REQ_RESP_STRUCT
	_, err1 := asn1.UnmarshalWithParams(data, &n,"application,explicit,tag:30")
	checkError(err1)
	if n.ERROR_CODE.Item == 6 {
		fmt.Println("Principal Unknown")
	} else if n.ERROR_CODE.Item == 25 {
		fmt.Println("Pre-Auth required")
	}
}