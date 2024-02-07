package grpc

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	labelPath   = "path"
	labelStatus = "status_code"
)

// Metrics stores the pointers to server metricOpts
type Metrics struct {
	requestCount     *prometheus.CounterVec
	requestHistogram *prometheus.HistogramVec
}

// NewMetrics takes in a prometheus metrics and initializes
// and registers metrics.
func NewMetrics(r prometheus.Registerer) *Metrics {
	return &Metrics{
		requestCount: promauto.With(r).NewCounterVec(
			prometheus.CounterOpts{
				Name: "approvals_api_request_count",
				Help: "the count of api requests",
			}, []string{labelPath, labelStatus},
		),
		requestHistogram: promauto.With(r).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "approvals_api_request_latency_ms",
				Help:    "the latency measurements",
				Buckets: []float64{100, 250, 500, 1000, 2000, 5000},
			}, []string{labelPath},
		),
	}
}

func (s *Server) entryMetrics() (time.Time, string) {
	return time.Now(), ""
}

func (s *Server) exitMetrics(start time.Time, status string) {
	s.metrics.requestCount.WithLabelValues(currentFunction(), status).Inc()
	s.metrics.requestHistogram.WithLabelValues().Observe(float64(time.Since(start).Milliseconds()))
}

func currentFunction() string {
	counter, _, _, success := runtime.Caller(1)
	if !success {
		return ""
	}
	funcName := runtime.FuncForPC(counter).Name()
	if funcName == "" {
		return ""
	}
	return funcName
}
