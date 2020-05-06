package main

import (
	"io"
	"log"

	"github.com/gliderlabs/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		io.WriteString(s, s.User()+"@"+s.LocalAddr().String()+"'s Password: ")
	})

	log.Fatal(ssh.ListenAndServe(":2222", nil))
}
