package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/procyon-projects/chrono"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/quara-dev/letsgo-nats/acme"
	"github.com/quara-dev/letsgo-nats/configuration"
	"github.com/quara-dev/letsgo-nats/fileserver"
	"github.com/quara-dev/letsgo-nats/stores"
)

// Certificates expiring in less than 21 days are renewed
const MINIMUM_REMAINING_DAYS = 21
const INITIAL_MINIMUM_REMAINING_DAYS = 21

func startRenewTask(ns *server.Server, config *configuration.UserConfig) {
	taskScheduler := chrono.NewDefaultTaskScheduler()

	_, err := taskScheduler.ScheduleWithFixedDelay(func(ctx context.Context) {
		ns.Debugf("Checking certificate expiration")
		renewed, err := acme.GetOrRenewCertificate(config, MINIMUM_REMAINING_DAYS)
		if err != nil {
			ns.Errorf("Failed to renew TLS certificates")
		} else if renewed {
			ns.Noticef("Reloading NATS server due to TLS certificates changes")
			ns.Reload()
		} else {
			ns.Noticef("Skipping TLS certificate request. Certificate is still valid for more than %d days", MINIMUM_REMAINING_DAYS)
		}
	}, 24*time.Hour)

	if err != nil {
		ns.Fatalf("Failed to schedule certificate renewal task")
	} else {
		ns.Noticef("Certificates will be checked for renewal each day")
	}
}

var usageStr = `
Usage: letsgo-nats [options]
Server Options:
    -a, --addr, --net <host>         Bind to host address (default: 0.0.0.0)
    -p, --port <port>                Use port for clients (default: 4222)
    -n, --name
        --server_name <server_name>  Server name (default: auto)
    -P, --pid <file>                 File to store PID
    -m, --http_port <port>           Use port for http monitoring
    -ms,--https_port <port>          Use port for https monitoring
    -c, --config <file>              Configuration file
    -t                               Test configuration and exit
    -sl,--signal <signal>[=<pid>]    Send signal to nats-server process (ldm, stop, quit, term, reopen, reload)
                                     pid> can be either a PID (e.g. 1) or the path to a PID file (e.g. /var/run/nats-server.pid)
        --client_advertise <string>  Client URL to advertise to other servers
        --ports_file_dir <dir>       Creates a ports file in the specified directory (<executable_name>_<pid>.ports).
Logging Options:
    -l, --log <file>                 File to redirect log output
    -T, --logtime                    Timestamp log entries (default: true)
    -s, --syslog                     Log to syslog or windows event log
    -r, --remote_syslog <addr>       Syslog server addr (udp://localhost:514)
    -D, --debug                      Enable debugging output
    -V, --trace                      Trace the raw protocol
    -VV                              Verbose trace (traces system account as well)
    -DV                              Debug and trace
    -DVV                             Debug and verbose trace (traces system account as well)
        --log_size_limit <limit>     Logfile size limit (default: auto)
        --max_traced_msg_len <len>   Maximum printable length for traced messages (default: unlimited)
JetStream Options:
    -js, --jetstream                 Enable JetStream functionality
    -sd, --store_dir <dir>           Set the storage directory
Authorization Options:
        --user <user>                User required for connections
        --pass <password>            Password required for connections
        --auth <token>               Authorization token required for connections
TLS Options:
        --tls                        Enable TLS, do not verify clients (default: false)
        --tlscert <file>             Server certificate file
        --tlskey <file>              Private key for server certificate
        --tlsverify                  Enable TLS, verify client certificates
        --tlscacert <file>           Client certificate CA for verification
Cluster Options:
        --routes <rurl-1, rurl-2>    Routes to solicit and connect
        --cluster <cluster-url>      Cluster URL for solicited routes
        --cluster_name <string>      Cluster Name, if not set one will be dynamically generated
        --no_advertise <bool>        Do not advertise known cluster information to clients
        --cluster_advertise <string> Cluster URL to advertise to other servers
        --connect_retries <number>   For implicit routes, number of connect retries
        --cluster_listen <url>       Cluster url from which members can solicit routes
Profiling Options:
        --profile <port>             Profiling HTTP port
Common Options:
    -h, --help                       Show this message
    -v, --version                    Show version
        --help_tls                   TLS help
`

// usage will print out the flag options for the server.
func usage() {
	fmt.Printf("%s\n", usageStr)
	os.Exit(0)
}

func main() {

	exe := "letsgo-nats"

	// Create a FlagSet and sets the usage
	fs := flag.NewFlagSet(exe, flag.ExitOnError)
	fs.Usage = usage

	// Process letsgo configuration
	stores := stores.DefaultStores()
	// Generate config for user
	config, err := configuration.NewUserConfig(&stores)
	if err != nil {
		log.Fatal(err)
	}
	// Generate TLS certificates using letsgo
	// Certificate is renewed if either:
	//   * renewed if it expires before 21 days
	//   * created if it does not exist yet
	//   * left untouched if it is still valid for more than 21 days
	_, err = acme.GetOrRenewCertificate(config, INITIAL_MINIMUM_REMAINING_DAYS)
	if err != nil {
		log.Fatal(err)
	}

	// Configure the options from the flags/config file
	opts, err := server.ConfigureOptions(fs, os.Args[1:],
		server.PrintServerAndExit,
		fs.Usage,
		server.PrintTLSHelpAndDie)
	if err != nil {
		server.PrintAndDie(fmt.Sprintf("%s: %s", exe, err))
	} else if opts.CheckConfig {
		fmt.Fprintf(os.Stderr, "%s: configuration file %s is valid\n", exe, opts.ConfigFile)
		os.Exit(0)
	}
	// I don't know how to access path to TLS certificates, only how to access already parsed x509 certificates
	// log.Printf("TLS Certificate: %s", opts.TLSConfig.Certificates)
	// log.Printf("TLS Key: %s", opts.TLSConfig.Certificates)
	// So we cannot process configuration BEFORE generating TLS certificates...

	// Create the server with appropriate options.
	ns, err := server.NewServer(opts)
	if err != nil {
		server.PrintAndDie(fmt.Sprintf("%s: %s", exe, err))
	}

	// Configure the logger based on the flags
	ns.ConfigureLogger()

	// Start things up. Block here until done.
	if err := server.Run(ns); err != nil {
		server.PrintAndDie(err.Error())
	}

	// Wait for server to be ready for connections
	if !ns.ReadyForConnections(4 * time.Second) {
		server.PrintAndDie("NATS server is not ready for connection before timeout (4s)")
	}
	// Start certificate renewal task
	startRenewTask(ns, config)

	// Adjust MAXPROCS if running under linux/cgroups quotas.
	undo, err := maxprocs.Set(maxprocs.Logger(ns.Debugf))
	if err != nil {
		ns.Warnf("Failed to set GOMAXPROCS: %v", err)
	} else {
		defer undo()
		// Reset these from the snapshots from init for monitor.go
		server.SnapshotMonitorInfo()
	}

	// Start fileserver
	if config.WebEnabled {
		fileserver.StartHTTPServer(config)
	}

	ns.WaitForShutdown()
}
