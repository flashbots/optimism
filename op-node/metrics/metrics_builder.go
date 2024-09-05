package metrics

import (
	"time"

	"github.com/ethereum-optimism/optimism/op-service/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

type BuilderMetrics struct {
	SequencerBuilderRequestDurationSeconds prometheus.Histogram
	SequencerBuilderRequestTotal           prometheus.Counter
	SequencerBuilderRequestErrors          prometheus.Counter
	SequencerBuilderRequestTimeouts        prometheus.Counter
	SequencerBuilderPayloadBytes           prometheus.Gauge
	SequencerProfit                        *prometheus.GaugeVec
	SequencerPayloadInserted               *prometheus.CounterVec
	SequencerPayloadGas                    *prometheus.GaugeVec
	SequencerPayloadGasTotal               *prometheus.GaugeVec
}

func NewBuilderMetrics(ns string, factory metrics.Factory) *BuilderMetrics {
	return &BuilderMetrics{
		SequencerBuilderRequestDurationSeconds: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "sequencer_builder_request_seconds",
			Buckets: []float64{
				.001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			Help: "Duration of sequencer builder requests",
		}),
		SequencerBuilderRequestTotal: factory.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "sequencer_builder_request_total",
			Help:      "Number of sequencer builder requests",
		}),
		SequencerBuilderRequestErrors: factory.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "sequencer_builder_request_errors",
			Help:      "Number of sequencer builder request errors",
		}),
		SequencerBuilderRequestTimeouts: factory.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "sequencer_builder_request_timeout",
			Help:      "Number of sequencer builder request timeouts",
		}),
		SequencerBuilderPayloadBytes: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "sequencer_builder_payload_bytes",
			Help:      "Size of sequencer builder payloads by source",
		}),
		SequencerProfit: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "sequencer_profit",
			Help:      "Sequencer profit by source.",
		}, []string{
			"source",
		}),
		SequencerPayloadInserted: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "sequencer_payload_inserted",
			Help:      "Count of sequencer payloads inserted to engine by source",
		}, []string{
			"source",
		}),
		SequencerPayloadGas: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "sequencer_payload_gas",
			Help:      "Gas used by sequencer payloads by source",
		}, []string{
			"source",
		}),
		SequencerPayloadGasTotal: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "sequencer_payload_gas_total",
			Help:      "Total gas used by sequencer payloads by source",
		}, []string{
			"source",
		}),
	}
}

func (bm *BuilderMetrics) RecordBuilderRequestTime(duration time.Duration) {
	bm.SequencerBuilderRequestTotal.Inc()
	bm.SequencerBuilderRequestDurationSeconds.Observe(float64(duration) / float64(time.Second))
}

func (bm *BuilderMetrics) RecordBuilderRequestFail() {
	bm.SequencerBuilderRequestErrors.Inc()
}

func (bm *BuilderMetrics) RecordBuilderRequestTimeout() {
	bm.SequencerBuilderRequestTimeouts.Inc()
}

func (bm *BuilderMetrics) RecordBuilderPayloadBytes(num int) {
	bm.SequencerBuilderPayloadBytes.Add(float64(num))
}

func (bm *BuilderMetrics) RecordSequencerProfit(profit float64, source PayloadSource) {
	bm.SequencerProfit.WithLabelValues(string(source)).Set(profit)
}

func (bm *BuilderMetrics) RecordSequencerPayloadInserted(source PayloadSource) {
	bm.SequencerPayloadInserted.WithLabelValues(string(source)).Inc()
}

func (bm *BuilderMetrics) RecordPayloadGas(gas float64, source string) {
	bm.SequencerPayloadGas.WithLabelValues(source).Set(gas)
	bm.SequencerPayloadGasTotal.WithLabelValues(source).Add(gas)
}
