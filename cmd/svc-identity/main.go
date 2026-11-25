// Command svc-identity is the Hostry identity service.
//
//	svc-identity serve                          run the HTTP API and the outbox relay
//	svc-identity migrate                        apply database migrations and exit
//	svc-identity vendor bootstrap --email ADDR  create the first platform_admin (setup link on the terminal)
//	svc-identity vendor recover   --email ADDR  return a platform_admin to setup-pending
//
// Configuration is environment only (12-factor); secrets are referenced by file path, never
// by value. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"syscall"
	"time"

	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/health"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-identity/internal/compose"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/repository/postgres"
	"github.com/hostryhq/svc-identity/service"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "svc-identity:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: svc-identity serve | migrate | vendor bootstrap|recover --email ADDR")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	switch args[0] {
	case "migrate":
		st, err := postgres.Open(ctx, cfg.DSN, "")
		if err != nil {
			return err
		}
		defer st.Close()
		return postgres.Migrate(ctx, st.DB())
	case "serve":
		return serve(ctx, cfg)
	case "vendor":
		return vendorCmd(ctx, cfg, args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func assemble(ctx context.Context, cfg *config, log *slog.Logger) (*compose.Result, *postgres.Store, error) {
	st, err := postgres.Open(ctx, cfg.DSN, cfg.DBRole)
	if err != nil {
		return nil, nil, err
	}
	sc, err := cfg.serviceConfig()
	if err != nil {
		return nil, nil, err
	}
	signer, err := cfg.signer()
	if err != nil {
		return nil, nil, err
	}
	reg, err := cfg.serviceRegistry()
	if err != nil {
		return nil, nil, err
	}
	ten, err := cfg.tenancy()
	if err != nil {
		return nil, nil, err
	}
	hc := health.New(2 * time.Second)
	hc.Add("postgres", st.Ping)
	sms, err := cfg.smsSender(log)
	if err != nil {
		return nil, nil, err
	}
	res, err := compose.Assemble(compose.Parts{
		Cfg: sc, Store: st, AccessLog: &postgres.AccessLog{DB: st.DB(), Role: cfg.DBRole}, Idem: postgres.NewIdempotency(st), Clock: clock.System,
		NewID: ids.New, Rand: crypto.System, SMS: sms, Notify: logNotifier{log}, Mail: terminalMail{}, Signer: signer,
		Services: reg, Tenancy: ten, Log: log, Health: hc, SMSAsync: true,
	})
	return res, st, err
}

func serve(ctx context.Context, cfg *config) error {
	log := logx.New(os.Stderr, slog.LevelInfo, "identity")
	res, st, err := assemble(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	if cfg.Migrate {
		if err := postgres.Migrate(ctx, st.DB()); err != nil {
			return err
		}
	}
	// Outbox relay: events reach the bus only through the outbox (ADR-0011 B4).
	if cfg.NATSURL != "" {
		if err := startRelay(ctx, cfg, st, log); err != nil {
			return err
		}
	} else {
		log.Warn("HOSTRY_NATS_URL is not set: events stay in the outbox and are not relayed")
	}
	go func() { // owner recoveries complete on identity's clock
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := res.Service.CompleteDueRecoveries(ctx); err != nil {
					log.Error("recovery completion failed", "error", err)
				}
			}
		}
	}()
	go func() { // idempotency records expire after 24 hours
		sweeper := postgres.NewIdempotency(st)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := sweeper.Sweep(ctx); err != nil {
					log.Error("idempotency sweep failed", "error", err)
				}
			}
		}
	}()
	srv := &http.Server{Addr: cfg.Listen, Handler: res.Handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("identity listening", "addr", cfg.Listen, "environment", cfg.Environment)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func startRelay(ctx context.Context, cfg *config, st *postgres.Store, log *slog.Logger) error {
	sink, closeFn, err := cfg.busSink()
	if err != nil {
		return err
	}
	relay := &outbox.Relay{DB: st.DB(), Sink: sink, LockKey: 7102002, Log: log}
	go func() {
		defer closeFn()
		if err := relay.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("outbox relay stopped", "error", err)
		}
	}()
	return nil
}

// vendorCmd implements `vendor bootstrap` and `vendor recover` (ADR-0005 A2.3). There is no HTTP
// route for either; the setup link is printed to the terminal only and never logged.
func vendorCmd(ctx context.Context, cfg *config, args []string) error {
	if len(args) == 0 || (args[0] != "bootstrap" && args[0] != "recover") {
		return errors.New("usage: svc-identity vendor bootstrap|recover --email ADDR [--environment NAME]")
	}
	fs := flag.NewFlagSet("vendor "+args[0], flag.ContinueOnError)
	email := fs.String("email", "", "email address of the platform admin")
	envName := fs.String("environment", "", "must equal the configured environment outside dev, test and ci")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	switch cfg.Environment {
	case "dev", "test", "ci":
	default:
		if *envName != cfg.Environment {
			return fmt.Errorf("outside dev, test and ci --environment must equal the configured environment %q", cfg.Environment)
		}
	}
	log := logx.New(os.Stderr, slog.LevelWarn, "identity")
	res, st, err := assemble(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	operator := "unknown"
	if u, err := user.Current(); err == nil {
		operator = u.Username
	}
	host, _ := os.Hostname()
	operator += "@" + host
	var tok string
	if args[0] == "bootstrap" {
		tok, err = res.Service.VendorBootstrap(ctx, *email, operator)
	} else {
		tok, err = res.Service.VendorRecover(ctx, *email, operator)
	}
	if err != nil {
		return err
	}
	fmt.Printf("One-time setup link token (24 hours, single use; open it in the admin panel):\n%s\n", tok)
	return nil
}

type logNotifier struct{ log *slog.Logger }

// Notify records a notification as a log line with ids only (no numbers, no free text); email and
// push delivery plug in behind service.Notifier when their providers exist.
func (n logNotifier) Notify(ctx context.Context, x service.Notice) {
	n.log.InfoContext(ctx, "notice", "kind", x.Kind, "tenant", x.TenantID, "account", x.AccountID, "member", x.MemberID, "device", x.DeviceID)
}

// terminalMail has no mail provider in Phase 1: setup links are shown by the CLI or created with
// a vendor user's own flow; nothing is mailed and nothing is logged.
type terminalMail struct{}

func (terminalMail) Send(context.Context, string, string, string) error { return nil }

var _ = token.TenantIssuer
