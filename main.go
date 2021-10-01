package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const version string = "-[SSL Check Service v1.1b]-"

var sslcheck *SSLService

const rootBucketName string = "DB"

var servicePort int

func init() {
	flag.IntVar(&servicePort, "port", 8093, "Puerto en que escucha el servicio. Debe ser un valor para puertos registrados (1024 – 49151) default: 8093")
	flag.Parse()
	if servicePort < 1024 || servicePort > 49151 {
		log.Fatalf("[ERROR] - Puerto inválido. El valor debe ser entre 1024 y 49151")
	}
}

func main() {

	srvPort := strconv.Itoa(servicePort)
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/service", serviceHandler)
	// SSL
	r.HandleFunc("/days/{host}", sslCheckHandler)

	srv := &http.Server{
		Addr: "0.0.0.0" + ":" + srvPort,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r), // Pass our instance of gorilla/mux in.
	}
	runServer(srv)
}

func runServer(srv *http.Server) {
	// Run our server in a goroutine so that it doesn't block.
	go func() {
		log.Printf("Starting service on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf(err.Error())
		}
	}()

	sslcheck, _ = NewService()
	// TODO: Add service to list
	sslcheck.Init()
	err := sslcheck.Start()
	if err != nil {
		fmt.Printf("No se pudo iniciar el servicio sslcheck: %s", err)
	}

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Println("shutting down")
	os.Exit(0)
}

// TODO: Structs para homogeneizar los mensajes de retorno.
// ver: https://semaphoreci.com/community/tutorials/building-and-testing-a-rest-api-in-go-with-gorilla-mux-and-postgresql
//
// func respondWithError(w http.ResponseWriter, code int, message string) {
//     respondWithJSON(w, code, map[string]string{"error": message})
// }

// func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
//     response, _ := json.Marshal(payload)

//     w.Header().Set("Content-Type", "application/json")
//     w.WriteHeader(code)
//     w.Write(response)
// }

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, version)
}

func serviceHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Running\n")
}

// SSL HANDLERS

func sslCheckHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	host := vars["host"]
	validez := sslcheck.Check(host)
	fmt.Fprintf(w, "%.f\n", math.Floor(validez.Hours()/24))
}
