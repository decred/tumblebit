// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/tumblebit/netparams"

	flags "github.com/jessevdk/go-flags"
)

var (
	tbHomeDir              = dcrutil.AppDataDir("tumblebit", false)
	dcrtumbleHomeDir       = dcrutil.AppDataDir("dcrtumble", false)
	dcrwalletHomeDir       = dcrutil.AppDataDir("dcrwallet", false)
	defaultConfigFile      = filepath.Join(dcrtumbleHomeDir, "dcrtumble.conf")
	defaultTumblerServer   = "localhost"
	defaultWalletRPCServer = "localhost"
	defaultTumblerCertFile = filepath.Join(tbHomeDir, "rpc.cert")
	defaultWalletCertFile  = filepath.Join(dcrwalletHomeDir, "rpc.cert")
)

// listCommands categorizes and lists all of the usable commands along with
// their one-line usage.
func listCommands() {
	fmt.Println()
}

// config defines the configuration options for dcrtumble.
//
// See loadConfig for details on the configuration load process.
type config struct {
	ShowVersion      bool   `short:"V" long:"version" description:"Display version information and exit"`
	ListCommands     bool   `short:"l" long:"listcommands" description:"List all of the supported commands and exit"`
	ConfigFile       string `short:"C" long:"configfile" description:"Path to configuration file"`
	TumblerRPCServer string `short:"s" long:"tumblerrpcserver" description:"TumbleBit RPC server to connect to"`
	WalletRPCServer  string `short:"w" long:"walletrpcserver" description:"Wallet RPC server to connect to"`
	TumblerRPCCert   string `long:"rpccert" description:"TumbleBit RPC server certificate chain for validation"`
	WalletRPCCert    string `long:"walletrpccert" description:"Wallet RPC server certificate chain for validation"`
	WalletPassword   string `long:"walletpass" description:"The private wallet password to unlocked the wallet"`
	Account          uint32 `short:"a" long:"account" description:"BIP0044 account number to use for transactions"`
	AccountName      string `long:"accountname" description:"Name of the account to use for transactions -- NOTE: This takes precedence over the numeric specification"`
	NoTLS            bool   `long:"notls" description:"Disable TLS"`
	TestNet          bool   `long:"testnet" description:"Connect to testnet"`
	SimNet           bool   `long:"simnet" description:"Connect to the simulation test network"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
//
// The above results in functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		ConfigFile:     defaultConfigFile,
		TumblerRPCCert: defaultTumblerCertFile,
		WalletRPCCert:  defaultWalletCertFile,
	}

	// Pre-parse the command line options to see if an alternative config
	// file, the version flag, or the list commands flag was specified.  Any
	// errors aside from the help message error can be ignored here since
	// they will be caught by the final parse below.
	preCfg := cfg
	preParser := flags.NewParser(&preCfg, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "The special parameter `-` "+
				"indicates that a parameter should be read "+
				"from the\nnext unread line from standard input.")
			os.Exit(1)
		} else if ok && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stdout, err)
			fmt.Fprintln(os.Stdout, "")
			fmt.Fprintln(os.Stdout, "The special parameter `-` "+
				"indicates that a parameter should be read "+
				"from the\nnext unread line from standard input.")
			os.Exit(0)
		}
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show options", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// Show the available commands and exit if the associated flag was
	// specified.
	if preCfg.ListCommands {
		listCommands()
		os.Exit(0)
	}

	if !fileExists(preCfg.ConfigFile) {
		err := createDefaultConfigFile(preCfg.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating a default config file: %v\n", err)
		}
	}

	// Load additional config from file.
	parser := flags.NewParser(&cfg, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(preCfg.ConfigFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			fmt.Fprintf(os.Stderr, "Error parsing config file: %v\n",
				err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, nil, err
	}

	// Multiple networks can't be selected simultaneously.
	numNets := 0
	if cfg.TestNet {
		activeNet = &netparams.TestNet2Params
		numNets++
	}
	if cfg.SimNet {
		activeNet = &netparams.SimNetParams
		numNets++
	}
	if numNets > 1 {
		str := "%s: the testnet and simnet params can't be used " +
			"together -- choose one of the two"
		err := fmt.Errorf(str, "loadConfig")
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Handle environment variable expansion in the RPC certificate path.
	cfg.TumblerRPCCert = cleanAndExpandPath(cfg.TumblerRPCCert)
	cfg.WalletRPCCert = cleanAndExpandPath(cfg.WalletRPCCert)

	// Add default port to RPC server based on --testnet and --simnet flags
	// if needed.
	if cfg.TumblerRPCServer == "" {
		cfg.TumblerRPCServer = net.JoinHostPort("localhost",
			activeNet.TumblerServerPort)
	}
	if cfg.WalletRPCServer == "" {
		cfg.WalletRPCServer = net.JoinHostPort("localhost",
			activeNet.WalletClientPort)
	}

	return &cfg, remainingArgs, nil
}

// createDefaultConfig creates a basic config file at the given destination
// path. For this it tries to read the dcrwallet config file at its default
// path and extract the wallet password.
func createDefaultConfigFile(destinationPath string) error {
	// Nothing to do when there is no existing TumbleBit conf file at the
	// default path to extract the details from.
	dcrwalletConfigPath := filepath.Join(dcrwalletHomeDir, "dcrwallet.conf")
	if !fileExists(dcrwalletConfigPath) {
		return nil
	}

	// Read dcrwallet.conf from its default path
	configFile, err := os.Open(dcrwalletConfigPath)
	if err != nil {
		return err
	}
	defer configFile.Close()
	content, err := ioutil.ReadAll(configFile)
	if err != nil {
		return err
	}

	// Extract the pass
	passRegexp, err := regexp.Compile(`(?m)^\s*pass=([^\s]+)`)
	if err != nil {
		return err
	}
	passSubmatches := passRegexp.FindSubmatch(content)
	if passSubmatches == nil {
		// No password found, nothing to do
		return nil
	}

	// Create the destination directory if it does not exists
	err = os.MkdirAll(filepath.Dir(destinationPath), 0700)
	if err != nil {
		return err
	}

	// Create the destination file and write the rpcuser and rpcpass to it
	dest, err := os.OpenFile(destinationPath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer dest.Close()

	dest.WriteString(fmt.Sprintf("walletpass=%s\n", string(passSubmatches[1])))

	return nil
}
