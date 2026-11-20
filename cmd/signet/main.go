package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/controller"
	"github.com/TwanBorst/signet/internal/httpapi"
	"github.com/TwanBorst/signet/internal/store"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func run() error {
	scope, err := deploymentScope()
	if err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()
	config, err := databaseConfig()
	if err != nil {
		return err
	}
	config.MaxConns = 10
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return errors.New("database initialization failed (credentials suppressed)")
	}
	defer pool.Close()
	db := &store.Store{Pool: pool}
	migrationCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err = db.Migrate(migrationCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	origins, err := publicOrigins(os.Getenv("PUBLIC_ORIGIN"), os.Getenv("PUBLIC_ORIGINS"))
	if err != nil {
		return err
	}
	header := os.Getenv("AUTH_HEADER")
	if header == "" {
		header = "x-auth-request-email"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(header) || !strings.HasPrefix(strings.ToLower(header), "x-") {
		return errors.New("AUTH_HEADER must be a valid custom x- header name")
	}
	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		return err
	}
	if err := api.AddToScheme(scheme); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New())
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, Cache: scope.CacheOptions(), Metrics: server.Options{BindAddress: "0"}, LeaderElection: false})
	if err != nil {
		return err
	}
	c := &controller.Controller{Store: db, Scope: scope}
	if err := c.Setup(ctx, mgr); err != nil {
		return err
	}
	handler := &httpapi.Server{Store: db, Namespace: scope.Namespace, AuthHeader: header, Origins: origins, UI: http.FileServer(http.Dir("/app/ui")), Live: c.Live}
	httpServer := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	if err := mgr.Add(&httpRunner{server: httpServer}); err != nil {
		return err
	}
	return mgr.Start(ctx)
}

func deploymentScope() (controller.Scope, error) {
	if _, exists := os.LookupEnv("ISSUER_INSTANCES"); exists {
		return controller.Scope{}, errors.New("ISSUER_INSTANCES is no longer supported; configure DEPLOYMENT_MODE and WATCH_NAMESPACE")
	}
	scope := controller.Scope{Mode: os.Getenv("DEPLOYMENT_MODE"), Namespace: os.Getenv("WATCH_NAMESPACE")}
	return scope, scope.Validate()
}

func databaseConfig() (*pgxpool.Config, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	host, name, user := os.Getenv("DATABASE_HOST"), os.Getenv("DATABASE_NAME"), os.Getenv("DATABASE_USERNAME")
	password, port, rootCert := os.Getenv("DATABASE_PASSWORD"), os.Getenv("DATABASE_PORT"), os.Getenv("DATABASE_SSLROOTCERT")
	if databaseURL != "" {
		if host != "" || name != "" || user != "" || password != "" || port != "" || rootCert != "" {
			return nil, errors.New("configure DATABASE_URL or individual DATABASE settings, not both")
		}
	} else {
		if host == "" || name == "" || user == "" || password == "" {
			return nil, errors.New("DATABASE_HOST, DATABASE_NAME, DATABASE_USERNAME and DATABASE_PASSWORD are required")
		}
		if net.ParseIP(host) == nil && !regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(host) {
			return nil, errors.New("DATABASE_HOST must be a hostname or IP address")
		}
		if port == "" {
			port = "5432"
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("DATABASE_PORT must be between 1 and 65535")
		}
		u := &url.URL{
			Scheme: "postgresql",
			User:   url.UserPassword(user, password),
			Host:   net.JoinHostPort(host, port),
		}
		query := url.Values{"sslmode": {"verify-full"}, "dbname": {name}}
		if rootCert != "" {
			query.Set("sslrootcert", rootCert)
		}
		u.RawQuery = query.Encode()
		databaseURL = u.String()
	}
	u, err := url.Parse(databaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Query().Get("sslmode") != "verify-full" {
		return nil, errors.New("DATABASE_URL must use postgres URI and sslmode=verify-full with a trusted database CA")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("invalid database configuration (value suppressed)")
	}
	if config.ConnConfig.TLSConfig == nil {
		return nil, errors.New("database requires sslmode=verify-full with a trusted database CA")
	}
	return config, nil
}

func publicOrigins(single, multiple string) ([]string, error) {
	if single != "" && multiple != "" {
		return nil, errors.New("configure only one of PUBLIC_ORIGIN and PUBLIC_ORIGINS")
	}
	var origins []string
	if multiple != "" {
		if err := json.Unmarshal([]byte(multiple), &origins); err != nil {
			return nil, errors.New("PUBLIC_ORIGINS must be a nonempty JSON list of HTTPS origins")
		}
	} else if single != "" {
		origins = []string{single}
	}
	if len(origins) == 0 {
		return nil, errors.New("PUBLIC_ORIGIN or a nonempty PUBLIC_ORIGINS is required")
	}
	pattern := regexp.MustCompile(`^https://([a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?|\[[0-9a-fA-F:]+\])(:[0-9]{1,5})?$`)
	seen := make(map[string]bool, len(origins))
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || !pattern.MatchString(origin) || u.Hostname() == "" {
			return nil, errors.New("public origins must be exact HTTPS origins without path, credentials, query, fragment or wildcard")
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return nil, errors.New("public origin port must be between 1 and 65535")
			}
		}
		if seen[origin] {
			return nil, errors.New("public origins must not contain duplicates")
		}
		seen[origin] = true
	}
	return origins, nil
}

type httpRunner struct {
	server *http.Server
}

func (h *httpRunner) NeedLeaderElection() bool { return false }
func (h *httpRunner) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := h.server.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP shutdown failed")
		}
	}()
	err := h.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		slog.Error("Signet startup failed", "reason", err.Error())
		os.Exit(1)
	}
}
