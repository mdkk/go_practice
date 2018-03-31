package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var timeout = flag.Int("d", 2, "-d assign the timeout")
var path = flag.String("P", "", "-P assign the path")
var host = flag.String("t", "", "-t assign the host(if only one host)")
var port = flag.String("p", "11211", "-p assign the port,default 11211")
var help = flag.Bool("h", false, "-d assign the timeout\n-P assign the path\n-t assign the host(if only one host)\n-p assign the port,default 11211\n")

func main() {
	flag.Parse()

	if *help {
		fmt.Println("-d assign the timeout\n-P assign the path\n-t assign the host(if only one host)\n-p assign the port,default 11211\n")
	}

	if *path != "" {
		fi, err := os.Open(*path)
		if err != nil {
			log.Fatal(err)
		}

		defer fi.Close()

		lines := bufio.NewReader(fi)

		for {
			line, _, c := lines.ReadLine()
			if c == io.EOF {
				break
			}
			target := fmt.Sprintf("%s:%s", string(line), *port)
			go scan(target)
			// go scan(string(line))
			// iplist = scan(string(line))
		}
		var n int
		for {
			select {
			case <-time.After(time.Second * 4):
				println("read channel timeout")
				fmt.Printf("%d done\n", n)
				os.Exit(1)
			case <-tokens:
				n++
			}
		}
	} else {
		if *host != "" {
			target := fmt.Sprintf("%s:%s", *host, *port)
			fmt.Printf("scaning %s\n", target)
			scan(target)
		} else {
			if !*help {
				fmt.Println("use -P or -t assign the target")
			}
		}
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered in memcache：", r)

		}
	}()

	// var iplist []string

	// var inputwait = func() {}
	// inputwait = func() {
	// 	var ipt string
	// 	fmt.Println("请输入")
	// 	_, err := fmt.Scanln(&ipt)
	// 	if err != nil {
	// 		fmt.Println(err)

	// 	}
	// 	if ipt == "" { //阻塞主goroutine，输入空字符退出
	// 		// inputwait()
	// 		os.Exit(1)
	// 	}
	// }
	// inputwait()

}

var tokens = make(chan struct{}, 2000) //most goroutine 2000

func scan(ip string) {
	tokens <- struct{}{} //get token

	// fmt.Printf("scaning %s\n", ip)
	udpAddr, err := net.ResolveUDPAddr("udp4", ip)
	if err != nil {
		fmt.Println(err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < 15; i++ { //send 15 times
		if _, err := conn.Write([]byte("\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n")); err != nil {
			fmt.Println(err)
		}
	}

	var buf = make([]byte, 512)

	deadline := time.Now().Add(2 * time.Second)
	conn.SetDeadline(deadline)
	_, err3 := conn.Read(buf[0:])

	if err3 != nil {
		// fmt.Println(err3)
		fmt.Printf("timeout,%s not vul\n", ip)

	} else {
		fmt.Println(ip)
		fmt.Println(string(buf[0:]))
	}
	<-tokens //release token
}
