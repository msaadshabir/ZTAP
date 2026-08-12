package main

import (
	"flag"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"ztap/internal/logging"
	ztapv1alpha1 "ztap/internal/operator/api/v1alpha1"
	"ztap/internal/operator/controllers"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	// Version is set at build time via -ldflags "-X main.Version=<value>".
	Version = "dev"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ztapv1alpha1.AddToScheme(scheme))
}

// operatorLoggingConfig mirrors the main binary's logging defaults plus its
// ZTAP_LOG_* environment overrides, so both binaries share format/config.
func operatorLoggingConfig() logging.Config {
	cfg := logging.DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_LEVEL")); v != "" {
		cfg.Level = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FORMAT")); v != "" {
		cfg.Format = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FILE")); v != "" {
		cfg.File = v
	}
	return cfg
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.Parse()

	// Share ZTAP's structured logging core: the same config sources and the
	// same JSON/text schema as the main binary, via logr over slog.
	logger, err := logging.New(operatorLoggingConfig())
	if err != nil {
		setupLog.Error(err, "unable to configure logging")
		os.Exit(1)
	}
	ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 server.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "ztap-operator-leader-election",
		LeaderElectionNamespace: "ztap-system",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.ZtapNetworkPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ZtapNetworkPolicy")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "version", Version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
