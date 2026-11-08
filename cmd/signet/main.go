package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	ctx := ctrl.SetupSignalHandler()
	config, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("invalid DATABASE_URL configuration (value suppressed)")
	}
	u, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Query().Get("sslmode") != "verify-full" || config.ConnConfig.TLSConfig == nil {
		return errors.New("DATABASE_URL must use postgres URI and sslmode=verify-full with a trusted database CA")
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
		return errors.New("database migration failed; check schema, connectivity and migration role permissions")
	}
	var instances []controller.Instance
	if err := json.Unmarshal([]byte(os.Getenv("ISSUER_INSTANCES")), &instances); err != nil || len(instances) == 0 {
		return errors.New("ISSUER_INSTANCES must be a nonempty JSON list")
	}
	for _, i := range instances {
		if i.Name == "" || (i.Kind != "SignetIssuer" && i.Kind != "SignetClusterIssuer") || (i.Kind == "SignetIssuer" && i.Namespace == "") || (i.Kind == "SignetClusterIssuer" && i.Namespace != "") {
			return errors.New("issuer instance must specify exact kind, name, and correct namespace scope")
		}
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
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, Metrics: server.Options{BindAddress: "0"}, LeaderElection: false})
	if err != nil {
		return err
	}
	c := &controller.Controller{Store: db, Instances: instances}
	if err := c.Setup(ctx, mgr); err != nil {
		return err
	}
	handler := &httpapi.Server{Store: db, AuthHeader: header, Origins: origins, UI: http.FileServer(http.Dir("/app/ui")), Live: c.Live}
	httpServer := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	if err := mgr.Add(&httpRunner{server: httpServer}); err != nil {
		return err
	}
	return mgr.Start(ctx)
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
