package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func connectKerberos() net.Conn {
	conn, _ := net.Dial("tcp", "192.168.56.106:88")
	return conn
}

func sendReq(connect net.Conn) {
	fmt.Println(connect)
	//	000000d0
	kerberosProtoVersion := "05"
	messageType := "0a"
	message := "6a81cd3081caa1030201"+kerberosProtoVersion+"a2030201"+messageType+"a31530133011a10402020080a20904073005a0030101ffa481a63081a3a00703050040810010a111300fa003020101a10830061b0475736572a2061b0454455354a3193017a003020102a110300e1b066b72627467741b0454455354a511180f32303337303931333032343830355aa611180f32303337303931333032343830355aa70602040aef4a2ea81530130201120201110201170201180202ff79020103a91d301b3019a003020114a1120410434c49454e5431202020202020202020"
	messageLen := uint32(len(message)/2) // 208
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, messageLen)
	fmt.Println(bs)
	data,_ := hex.DecodeString(message)
	data = append(bs,data...)
	connect.Write(data)
	time.Sleep(1*time.Second)
}

func main() {
	fmt.Println("[:]\\/\\/\\/\\[:]")
	myConnect := connectKerberos()
	sendReq(myConnect)
}
