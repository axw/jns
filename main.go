package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/juju/names"
	"github.com/juju/persistent-cookiejar"
	"github.com/miekg/dns"
	"gopkg.in/macaroon-bakery.v1/httpbakery"

	"github.com/juju/errors"
	"github.com/juju/juju/api"
	"github.com/juju/juju/cmd/envcmd"
	"github.com/juju/juju/environs/configstore"
	"github.com/juju/juju/juju"
	_ "github.com/juju/juju/provider/all"
)

var (
	listenAddr  string
	zone        string
	includeLost bool
)

func init() {
	flag.StringVar(&listenAddr, "listen", ":53", "specify the address/port to listen on")
	flag.StringVar(&zone, "zone", "juju.", "specify a zone pattern")
	flag.BoolVar(&includeLost, "include-lost", false,
		"include \"lost\" units in service queries")
	rand.Seed(time.Now().UnixNano())
}

type jujuNameServer struct {
	dns.Server
	configstore configstore.Storage
}

func (s *jujuNameServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	for _, q := range r.Question {
		rr, err := s.answer(q)
		if err != nil {
			m.SetRcodeFormatError(r)
			t := new(dns.TXT)
			t.Hdr = dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassNONE,
			}
			t.Txt = []string{err.Error()}
			m.Extra = append(m.Extra, t)
			continue
		} else if rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}
	m.Authoritative = true
	// recursion isn't really available, but it's apparently
	// necessary to set this to make nslookup happy.
	m.RecursionAvailable = true
	w.WriteMsg(m)
}

// TODO(axw) define an error for "no answer"
func (s *jujuNameServer) answer(q dns.Question) (dns.RR, error) {
	if q.Qtype != dns.TypeA {
		return nil, nil
	}

	var envName string
	entityName := strings.TrimSuffix(q.Name, "."+zone)
	if i := strings.IndexRune(entityName, '.'); i >= 0 {
		envName = entityName[i+1:]
		entityName = entityName[:i]
	} else {
		var err error
		envName, err = envcmd.GetDefaultEnvironment()
		if err != nil {
			return nil, err
		}
	}

	// TODO(axw) cache API connection
	api, err := s.openAPI(envName)
	if err != nil {
		return nil, err
	}
	defer api.Close()
	client := api.Client()

	var addr string
	if names.IsValidService(entityName) {
		status, err := client.Status([]string{entityName})
		if err != nil {
			return nil, err
		}
		service := status.Services[entityName]
		addresses := make([]string, 0, len(service.Units))
		for _, unit := range service.Units {
			if unit.PublicAddress == "" {
				continue
			}
			if includeLost || unit.UnitAgent.Status != "lost" {
				addresses = append(addresses, unit.PublicAddress)
			}
		}
		// Might be nice to have additional info in TXT?
		if len(addresses) == 0 {
			return nil, nil
		}
		addr = addresses[rand.Intn(len(addresses))]
	} else {
		// Assume it's a machine or unit name.
		addr, err = client.PublicAddress(entityName)
		if err != nil {
			return nil, err
		}
	}

	ip := net.ParseIP(addr)
	if ip != nil {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		rr.A = ip
		return rr, nil
	} else {
		rr := new(dns.CNAME)
		rr.Hdr = dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		rr.Target = addr + "."
		return rr, nil
	}
}

func shuffle(ss []string) {
	n := len(ss)
	for i := n - 1; i >= 1; i-- {
		j := rand.Intn(i + 1)
		ss[i], ss[j] = ss[j], ss[i]
	}
}

func (s *jujuNameServer) openAPI(envName string) (api.Connection, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: cookiejar.DefaultCookieFile(),
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	client := httpbakery.NewClient()
	client.Jar = jar
	client.VisitWebPage = httpbakery.OpenWebBrowser
	return juju.NewAPIFromName(envName, client)
}

func main() {
	flag.Parse()
	if err := juju.InitJujuHome(); err != nil {
		log.Fatal(err)
	}

	store, err := configstore.Default()
	if err != nil {
		log.Fatal(err)
	}

	var server jujuNameServer
	server.Addr = listenAddr
	server.Net = "udp"
	server.configstore = store

	log.Println("listening for requests on:", listenAddr)
	dns.HandleFunc(zone, server.handleRequest)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
