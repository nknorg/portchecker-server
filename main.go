package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var listenAddr = flag.String("listen-addr", ":80", "http server listen address")
var httpReadTimeout = flag.Int("http-read-timeout", 10, "http read timeout in seconds")
var httpWriteTimeout = flag.Int("http-write-timeout", 30, "http write timeout in seconds")
var portDialTimeout = flag.Int("port-dial-timeout", 10, "check port dial timeout in seconds")
var portConnTimeout = flag.Int("port-conn-timeout", 30, "check port conn timeout in seconds")

type Req struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Nonce    string `json:"nonce"`
}

type Resp struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func checkPort(r *http.Request) (int, *Resp, error) {
	resp := &Resp{Success: false}

	clientIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	if clientIP == nil {
		resp.Error = fmt.Sprintf("failed to parse client IP address")
		return http.StatusBadRequest, resp, fmt.Errorf("failed to parse client IP address from %s", r.RemoteAddr)
	}

	req := &Req{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(req)
	if err != nil {
		resp.Error = fmt.Sprintf("request body is not a valid json")
		return http.StatusBadRequest, resp, fmt.Errorf("decode request error: %v", err)
	}

	protocol := strings.ToLower(req.Protocol)
	addr := fmt.Sprintf("%s:%v", clientIP.String(), req.Port)

	var conn net.Conn
	switch protocol {
	case "tcp", "udp":
		conn, err = net.DialTimeout(protocol, addr, time.Duration(*portDialTimeout)*time.Second)
	default:
		resp.Error = fmt.Sprintf("unknown protocol: %s", protocol)
		return http.StatusBadRequest, resp, fmt.Errorf(resp.Error)
	}
	if err != nil {
		resp.Error = fmt.Sprintf("dial error: %v", err)
		return http.StatusOK, resp, nil
	}

	conn.SetDeadline(time.Now().Add(time.Duration(*portConnTimeout) * time.Second))

	_, err = conn.Write([]byte(req.Nonce))
	if err != nil {
		resp.Error = fmt.Sprintf("write error: %v", err)
		return http.StatusOK, resp, nil
	}

	b := make([]byte, 64)
	n, err := conn.Read(b)
	if err != nil {
		resp.Error = fmt.Sprintf("read error: %v", err)
		return http.StatusOK, resp, nil
	}

	_, err = conn.Write(b[:n])
	if err != nil {
		resp.Error = fmt.Sprintf("write error: %v", err)
		return http.StatusOK, resp, nil
	}

	resp.Success = true
	return http.StatusOK, resp, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	statusCode, resp, err := checkPort(r)
	if err != nil {
		log.Printf("Check port error: %v", err)
	}
	if resp != nil {
		b, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(statusCode)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(b)
		if err != nil {
			log.Printf("Write response error: %v", err)
		}
	} else {
		w.WriteHeader(statusCode)
	}
}

func main() {
	flag.Parse()
	http.HandleFunc("/", handler)
	s := &http.Server{
		Addr:         *listenAddr,
		ReadTimeout:  time.Duration(*httpReadTimeout) * time.Second,
		WriteTimeout: time.Duration(*httpWriteTimeout) * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}
