package main

import (
	"fmt"
	"github.com/End3ymion/go-cryptpgp/app"
)

func main() {
	fmt.Println("[MAIN] Starting main()")
	// Entry point of the application.
	app.Run()
	fmt.Println("[MAIN] app.Run() returned")
}
