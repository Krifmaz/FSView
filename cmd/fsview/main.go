// Command fsview is a disk, filesystem and storage-pool manager for
// Proxmox VE hosts.
//
//	fsview serve  [-config /etc/fsview/fsview.conf]   unprivileged web server
//	fsview helper [-config /etc/fsview/helper.conf]   root helper
//	fsview user add|passwd|del|list NAME [--generate]
//	fsview version
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/krifmaz/fsview/internal/auth"
	"github.com/krifmaz/fsview/internal/config"
	"github.com/krifmaz/fsview/internal/helper"
	"github.com/krifmaz/fsview/internal/helperclient"
	"github.com/krifmaz/fsview/internal/netutil"
	"github.com/krifmaz/fsview/internal/runner"
	"github.com/krifmaz/fsview/internal/store"
	"github.com/krifmaz/fsview/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "helper":
		err = cmdHelper(os.Args[2:])
	case "user":
		err = cmdUser(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("fsview", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fsview:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  fsview serve  [-config /etc/fsview/fsview.conf]
  fsview helper [-config /etc/fsview/helper.conf]
  fsview user add|passwd NAME [--generate] [-config ...]
  fsview user del NAME | list
  fsview version
`)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/fsview/fsview.conf", "config file")
	fs.Parse(args)
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run the web server as root; run it as the fsview user")
	}
	cfg, err := config.LoadWeb(*cfgPath)
	if err != nil {
		return err
	}
	lanAddr, lanNet, lanErr := netutil.LANAddress()
	if lanErr != nil {
		fmt.Fprintln(os.Stderr, "fsview: LAN detection:", lanErr)
	}
	listen, err := netutil.ResolveListen(cfg.Listen, cfg.Port, lanAddr)
	if err != nil {
		return err
	}
	allow, err := netutil.ResolveAllow(cfg.Allow, lanNet)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	if len(st.Users()) == 0 {
		fmt.Fprintln(os.Stderr, "fsview: warning: no users exist; create one with `fsview user add admin --generate`")
	}
	srv := web.New(web.Options{
		Version: version, Allow: allow, Listen: listen, TLSCert: cfg.TLSCert, TLSKey: cfg.TLSKey,
		SmartPoll: cfg.SmartPoll, JournalPoll: cfg.JournalPoll,
	}, st, &helperclient.Client{Socket: cfg.HelperSocket})
	ctx, cancel := signalContext()
	defer cancel()
	return srv.Run(ctx)
}

func cmdHelper(args []string) error {
	fs := flag.NewFlagSet("helper", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/fsview/helper.conf", "config file")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return fmt.Errorf("the helper must run as root")
	}
	cfg, err := config.LoadHelper(*cfgPath)
	if err != nil {
		return err
	}
	u, err := user.Lookup(cfg.ClientUser)
	if err != nil {
		return fmt.Errorf("client user %q: %w", cfg.ClientUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 {
		return fmt.Errorf("client_user must not be root")
	}
	audit, err := helper.NewAuditLog(cfg.AuditLog, gid)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o755); err != nil {
		return err
	}
	srv := helper.New(helper.Config{
		Socket: cfg.Socket, AllowedUIDs: []int{uid}, SocketGID: gid,
		WritesEnabled: cfg.WritesEnabled, IncludeLoop: cfg.IncludeLoop, Version: version,
	}, runner.Exec{}, audit)
	l, err := srv.Listen()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "fsview-helper %s: listening on %s for uid %d (writes_enabled=%v)\n", version, cfg.Socket, uid, cfg.WritesEnabled)
	ctx, cancel := signalContext()
	defer cancel()
	return srv.Serve(ctx, l)
}

func cmdUser(args []string) error {
	if len(args) < 1 {
		usage()
		return fmt.Errorf("missing user subcommand")
	}
	sub := args[0]
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/fsview/fsview.conf", "config file")
	generate := fs.Bool("generate", false, "generate a random password and print it")
	// Allow flags after the user name.
	var name string
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		name, rest = rest[0], rest[1:]
	}
	fs.Parse(rest)
	cfg, err := config.LoadWeb(*cfgPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer fixOwnership(cfg.DataDir)
	switch sub {
	case "list":
		for _, u := range st.Users() {
			fmt.Printf("%s\tcreated %s\n", u.Name, u.CreatedAt.Format("2006-01-02"))
		}
		return nil
	case "del":
		if name == "" {
			return fmt.Errorf("user name required")
		}
		return st.DeleteUser(name)
	case "add", "passwd":
		if name == "" {
			return fmt.Errorf("user name required")
		}
		var pw string
		if *generate {
			if pw, err = auth.GeneratePassword(20); err != nil {
				return err
			}
		} else if pw, err = readPassword(); err != nil {
			return err
		}
		if err := st.SetPassword(name, pw, sub == "add"); err != nil {
			return err
		}
		if *generate {
			fmt.Printf("user %s password: %s\n", name, pw)
		} else {
			fmt.Printf("password for %s set\n", name)
		}
		return nil
	}
	return fmt.Errorf("unknown user subcommand %q", sub)
}

func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "New password: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Repeat: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", fmt.Errorf("passwords do not match")
		}
		return string(a), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// fixOwnership hands the data directory back to the fsview user when the
// CLI was run as root.
func fixOwnership(dir string) {
	if os.Geteuid() != 0 {
		return
	}
	u, err := user.Lookup("fsview")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}
