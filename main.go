package main

import (
	"fmt"

	"github.com/sinakeshmiri/goraz/packages/securitytrails"
)

func main() {
	fmt.Println(securitytrails.Find("", ""))
}
