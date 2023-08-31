package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func connectKerberos(targetServerPort string) net.Conn {
	conn, _ := net.Dial("tcp", targetServerPort)
	return conn
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

var barkTargetDC string
var barkAction string
var barkAccount string
var barkPassword string
var barkDomain string
var barkMachine string

func init() {
	flag.StringVar(&barkTargetDC, "dc", "192.168.56.106", "DC ip address")
	flag.StringVar(&barkAction, "action", "preauthCheck", "Bark action (checkAccount)")
	flag.StringVar(&barkAccount, "account", "user", "Account to check")
	flag.StringVar(&barkPassword, "password", "password", "Account's password")
	flag.StringVar(&barkDomain, "domain", "test", "Domain/Realm to use")
	flag.StringVar(&barkMachine, "netbios", "client1", "NetBIOS of local machine")
	flag.Parse()


}

func main() {
	fmt.Println("[:]\\/\\/\\/\\[:]")
	myConnect := connectKerberos(barkTargetDC+":88")
	//sendReq(myConnect)
	//barkAccount = "user"
	//barkPassword = "password"
	//barkDomain = "test"
	sendReqASN(myConnect,barkAccount,barkDomain,barkMachine)
	sendReqWithPreAuthASN(myConnect,barkAccount,barkDomain,barkMachine)
	myConnect.Close()

}
