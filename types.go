package main

import (
	"encoding/hex"
	"fmt"
)

type asReq struct {
	kerberosProtoVersion string
	messageType string
	paDataType string
	paDataValue string
	includePac string
	kdcOptions string
	cnameNameType string
	cnameCnameString string
	cnameRealm string
	snameNameType string
	snameString1 string
	snameString2 string
	snameTill string
	snameRTime string
	snameNonce string
	addressesAddrType string // IPv4-2,Directional-3,ChaosNet-5,XNS-6,ISO-7,DECNET Phase IV-12,AppleTalk DDP-16,NetBios-20,IPv6-24
	addressesNetBIOSName string
}



func (newReq *asReq) buildAsReq() string {
	cnameLength := len(newReq.cnameCnameString)/2
	fmt.Println(cnameLength)
	cnameStringLength := hex.EncodeToString([]byte(string(cnameLength)))
	seqLength := cnameLength + 2
	seqLengthH := hex.EncodeToString([]byte(string(seqLength)))
	slice1Len := seqLength + 2
	slice1LenH := hex.EncodeToString([]byte(string(slice1Len)))
	sec1Len := 11 + cnameLength
	sec1LenH := hex.EncodeToString([]byte(string(sec1Len)))
	slice2Len := 13 + cnameLength
	slice2LenH := hex.EncodeToString([]byte(string(slice2Len)))
	sec2Len := 159 + cnameLength
	sec2LenH := fmt.Sprintf("%x", sec2Len)
	slice3Len := 162 + cnameLength
	slice3LenH := fmt.Sprintf("%x", slice3Len)
	sec3Len := 198 + cnameLength
	sec3LenH := fmt.Sprintf("%x", sec3Len)
	sec4Len := 201 + cnameLength
	sec4LenH := fmt.Sprintf("%x", sec4Len)
		resultedString := "6a81"+
		sec4LenH+
		"3081"+
		sec3LenH+
		"a1030201"+ //as-req header
		newReq.kerberosProtoVersion+
		"a2030201"+
		newReq.messageType+
		"a31530133011a1040202"+
		newReq.paDataType+
		"a2090407"+
		newReq.paDataValue+
		newReq.includePac+
		"a481"+slice3LenH+"3081"+
		sec2LenH+
		"a007030500"+
		newReq.kdcOptions+
		"a1"+
		slice2LenH+
		"30"+
		sec1LenH+
		"a0030201"+
		newReq.cnameNameType+
		"a1"+
		slice1LenH+"30"+
		seqLengthH+"1b"+
		cnameStringLength+
		newReq.cnameCnameString+
		"a2061b04"+
		newReq.cnameRealm+
		"a3193017a0030201"+
		newReq.snameNameType+
		"a110300e1b06"+
		newReq.snameString1+
		"1b04"+
		newReq.snameString2+
		"a511180f"+
		newReq.snameTill+
		"a611180f"+
		newReq.snameRTime+
		"a7060204"+
		newReq.snameNonce+
		"a81530130201120201110201170201180202ff79020103a91d301b3019a0030201"+
		newReq.addressesAddrType+
		"a1120410"+
		newReq.addressesNetBIOSName
	return resultedString
}