package fileserver

import (
	"log"
	"net/http"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/digitalocean"
	"github.com/quara-dev/letsgo-nats/configuration"
)

func requestHandler(fs http.Handler) http.Handler {
	// This is a demo handler, it is not realistic
	fn := func(w http.ResponseWriter, req *http.Request) {
		log.Printf("Received new request on path %s", req.URL)
		fs.ServeHTTP(w, req)
	}
	return http.HandlerFunc(fn)
}

func StartHTTPServer(config *configuration.UserConfig) {

	// Use the http.NewServeMux() function to create an empty servemux.
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(config.WebRoot))
	mux.Handle("/", requestHandler(fs))

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider: &digitalocean.Provider{
			APIToken: config.AuthToken,
		},
	}

	// read and agree to your CA's legal documents
	certmagic.DefaultACME.Agreed = true

	// provide an email address
	certmagic.DefaultACME.Email = config.Email

	// use the staging endpoint while we're developing
	certmagic.DefaultACME.CA = config.CADirURL

	// if the decision function returns an error, a certificate
	// may not be obtained for that name at that time
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			// if !IsDomainAllowed(name){
			// 	return fmt.Errorf("Domain name not allowed %s", name)
			// }
			return nil
		},
	}
	// Start an HTTPS listener
	log.Printf("Starting certmagic")
	// encrypted HTTPS with HTTP->HTTPS redirects - yay! 🔒😍
	certmagic.HTTPS(config.Domains, mux)
}
