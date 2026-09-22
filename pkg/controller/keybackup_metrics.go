package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	keyBackupResultSuccess = "success"
	keyBackupResultFailure = "failure"
	keyBackupResultSkipped = "skipped"
)

var (
	keyBackupTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_total",
			Help:      "Sealing key backup attempts by result (success, failure, skipped).",
		},
		[]string{"result"},
	)
	keyBackupLastSuccess = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_last_success_timestamp_seconds",
			Help:      "Unix time of the last successful sealing key backup.",
		},
	)
	keyBackupUnbackedKeys = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_unbacked_keys",
			Help:      "Registered sealing keys with no confirmed backup. Zero is healthy.",
		},
	)
)

// registerKeyBackupMetrics is called once from Main, only when backup is enabled.
func registerKeyBackupMetrics() {
	prometheus.MustRegister(keyBackupTotal, keyBackupLastSuccess, keyBackupUnbackedKeys)
}

func observeKeyBackupSuccess() {
	keyBackupTotal.WithLabelValues(keyBackupResultSuccess).Inc()
	keyBackupLastSuccess.Set(float64(time.Now().Unix()))
}
