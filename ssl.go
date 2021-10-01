package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"syscall"
	"time"
)

// Status representa el estado de un servicio
type serviceStatus int

const (
	// Desconocido el servicio está en un estado desconocido
	desconocido serviceStatus = iota
	// Ejecutando el servicio se encuentra corriendo
	ejecutando
	// Detenido el servicio se encuentra detenido
	detenido
)

var lookupTimeout = 10 * time.Second
var connectionTimeout = 30 * time.Second
var warningFlag = 30
var criticalFlag = 14
var printVersion = false

var warningValidity = time.Duration(warningFlag) * 24 * time.Hour
var criticalValidity = time.Duration(criticalFlag) * 24 * time.Hour

// SSLService is a SSL Check Service
type SSLService struct {
	status serviceStatus
}

// NewService returns a new service instance
func NewService() (*SSLService, error) {
	service := &SSLService{
		status: desconocido,
	}
	return service, nil
}

// Init intis service
func (ssl *SSLService) Init() error {
	ssl.status = detenido
	return nil
}

// Start starts service
func (ssl *SSLService) Start() error {
	if ssl.status == detenido {
		ssl.status = ejecutando
	}
	return nil
}

func lookupIPWithTimeout(host string, timeout time.Duration) []net.IP {
	timer := time.NewTimer(timeout)

	ch := make(chan []net.IP, 1)
	go func() {
		r, err := net.LookupIP(host)
		if err != nil {
			log.Fatal(err)
		}
		ch <- r
	}()
	select {
	case ips := <-ch:
		return ips
	case <-timer.C:
		log.Printf("timeout resolving %s", host)
	}
	return make([]net.IP, 0)
}

// Check function checs SSL for a domain and returns remaining validity.
func (ssl *SSLService) Check(host string) (remainingValidity time.Duration) {
	ips := lookupIPWithTimeout(host, lookupTimeout)
	for _, ip := range ips {
		dialer := net.Dialer{Timeout: connectionTimeout, Deadline: time.Now().Add(connectionTimeout + 5*time.Second)}
		connection, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("[%s]:443", ip), &tls.Config{ServerName: host})
		if err != nil {
			// catch missing ipv6 connectivity
			// if the ip is ipv6 and the resulting error is "no route to host", the record is skipped
			// otherwise the check will switch to critical
			if ip.To4() == nil {
				switch err.(type) {
				case *net.OpError:
					// https://stackoverflow.com/questions/38764084/proper-way-to-handle-missing-ipv6-connectivity
					if err.(*net.OpError).Err.(*os.SyscallError).Err == syscall.EHOSTUNREACH {
						log.Printf("%-15s - ignoring unreachable IPv6 address", ip)
						continue
					}
				}
			}
			log.Printf("%s: %s", ip, err)
			continue
		}
		// rembember the checked certs based on their Signature
		checkedCerts := make(map[string]struct{})
		// loop to all certs we get
		// there might be multiple chains, as there may be one or more CAs present on the current system, so we have multiple possible chains
		for _, chain := range connection.ConnectionState().VerifiedChains {
			for _, cert := range chain {
				if _, checked := checkedCerts[string(cert.Signature)]; checked {
					continue
				}
				checkedCerts[string(cert.Signature)] = struct{}{}
				// filter out CA certificates
				if cert.IsCA {
					log.Printf("%-15s - ignoring CA certificate %s", ip, cert.Subject.CommonName)
					continue
				}
				remainingValidity = cert.NotAfter.Sub(time.Now())
				log.Printf("%-15s - %s valid until %s (%s)", ip, cert.Subject.CommonName, cert.NotAfter, formatDuration(remainingValidity))
			}
		}
		connection.Close()
	}
	return
}

func formatDuration(in time.Duration) string {
	var daysPart, hoursPart, minutesPart, secondsPart string

	days := math.Floor(in.Hours() / 24)
	hoursRemaining := math.Mod(in.Hours(), 24)
	if days > 0 {
		daysPart = fmt.Sprintf("%.fd", days)
	} else {
		daysPart = ""
	}

	hours, hoursRemaining := math.Modf(hoursRemaining)
	minutesRemaining := hoursRemaining * 60
	if hours > 0 {
		hoursPart = fmt.Sprintf("%.fh", hours)
	} else {
		hoursPart = ""
	}

	if minutesRemaining > 0 {
		minutesPart = fmt.Sprintf("%.fm", minutesRemaining)
	}

	_, minutesRemaining = math.Modf(minutesRemaining)
	secondsRemaining := minutesRemaining * 60
	if secondsRemaining > 0 {
		secondsPart = fmt.Sprintf("%.fs", secondsRemaining)
	}

	return fmt.Sprintf("%s %s %s %s", daysPart, hoursPart, minutesPart, secondsPart)
}
