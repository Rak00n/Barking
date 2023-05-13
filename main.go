package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"time"
)

func connectKerberos(targetServerPort string) net.Conn {
	conn, _ := net.Dial("tcp", targetServerPort)
	return conn
}



func sendReq(connect net.Conn) {

	var newRequest asReq
	newRequest.kerberosProtoVersion = "05"
	newRequest.messageType = "0a"
	newRequest.paDataType = "0080"
	newRequest.paDataValue = "3005a0030101"
	newRequest.includePac = "ff" // true
	newRequest.kdcOptions = "40810010"
	newRequest.cnameNameType = "01"
	newRequest.cnameCnameString = hex.EncodeToString([]byte("user"))
	newRequest.cnameRealm = hex.EncodeToString([]byte("TEST"))
	newRequest.snameNameType = "02"
	newRequest.snameString1 = hex.EncodeToString([]byte("krbtgt"))
	newRequest.snameString2 = hex.EncodeToString([]byte("TEST"))
	newRequest.snameTill = hex.EncodeToString([]byte("20370913024805Z"))
	newRequest.snameRTime = hex.EncodeToString([]byte("20370913024805Z"))
	newRequest.snameNonce = "0aef4a2e"
	newRequest.addressesAddrType = "14" // 14 - nETBIOS
	newRequest.addressesNetBIOSName = hex.EncodeToString([]byte("CLIENT1         ")) // 434c49454e5431202020202020202020 field may be longer, no error here
	message := newRequest.buildAsReq()
	//fmt.Println(message)
	fmt.Println(message)
	messageLen := uint32(len(message)/2) // 208
	fmt.Println(messageLen)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, messageLen)
	fmt.Println(bs)
	data,_ := hex.DecodeString(message)
	data = append(bs,data...)
	fmt.Println(data)
	fmt.Println(hex.EncodeToString(data))
	connect.Write(data)
	time.Sleep(1*time.Second)
}

var barkTargetDC string
var barkAction string
var barkAccount string
var barkDomain string
var barkMachine string

func init() {
	flag.StringVar(&barkTargetDC, "dc", "192.168.56.106", "DC ip address")
	flag.StringVar(&barkAction, "action", "preauthCheck", "Bark action (checkAccount)")
	flag.StringVar(&barkAccount, "account", "user", "Account to check")
	flag.StringVar(&barkDomain, "domain", "test", "Domain/Realm to use")
	flag.StringVar(&barkMachine, "netbios", "client1", "NetBIOS of local machine")
	flag.Parse()


}

func main() {
	fmt.Println("[:]\\/\\/\\/\\[:]")
	myConnect := connectKerberos(barkTargetDC+":88")
	//sendReq(myConnect)
	barkAccount = "user"
	barkDomain = "test"
	sendReqASN(myConnect,barkAccount,barkDomain,barkMachine)
	myConnect.Close()
}
