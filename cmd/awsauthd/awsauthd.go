package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/crewjam/awsconsoleauth"
)

func main() {
	listenAddress := flag.String("listen", ":8080", "The address the web server should listen on")
	flag.Parse()

	if err := awsconsoleauth.Initialize(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Listening on %s\n", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
