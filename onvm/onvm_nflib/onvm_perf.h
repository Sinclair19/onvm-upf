#ifndef _ONVM_PERF_H_
#define _ONVM_PERF_H_

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_mbuf.h>

// every 'N'th packet sampled
#define ONVM_PERF_DEFAULT_SAMPLE_RATE 100 

#define ONVM_PERF_PRINT_INTERVAL_SEC 1
#define ONVM_PERF_TRACE_MARKER UINT64_MAX

struct onvm_perf_sampler {
        uint32_t sample_rate;
        uint32_t countdown;
        uint8_t initialized;
};

struct onvm_perf_stats {
        const char *name;
        uint64_t packets;
        uint64_t samples;
        uint64_t total_cycles;
        uint64_t min_cycles;
        uint64_t max_cycles;
        uint64_t period_samples;
        uint64_t period_total_cycles;
        uint64_t period_min_cycles;
        uint64_t period_max_cycles;
        uint64_t last_print_cycles;
        uint32_t sample_rate;
        uint32_t countdown;
        uint8_t initialized;
        FILE *out;
        uint8_t file_output;
};

static inline uint32_t
onvm_perf_get_sample_rate(void) {
        const char *sample_rate_env;
        uint32_t sample_rate = ONVM_PERF_DEFAULT_SAMPLE_RATE;

        sample_rate_env = getenv("ONVM_COMP_SAMPLE_RATE");
        if (sample_rate_env != NULL) {
                long parsed = strtol(sample_rate_env, NULL, 10);
                if (parsed >= 0)
                        sample_rate = (uint32_t)parsed;
        }

        return sample_rate;
}

static inline void
onvm_perf_init(struct onvm_perf_stats *stats, const char *name) {
        const char *stats_dir_env;

        if (stats->initialized)
                return;

        stats->name = name;
        stats->min_cycles = UINT64_MAX;
        stats->period_min_cycles = UINT64_MAX;
        stats->last_print_cycles = rte_get_tsc_cycles();
        stats->sample_rate = onvm_perf_get_sample_rate();

        stats_dir_env = "/home/ubuntu/mylog"; //getenv("ONVM_COMP_STATS_DIR");
        if (stats_dir_env != NULL && stats_dir_env[0] != '\0') {
                char path[512];
                int n = snprintf(path, sizeof(path), "%s/component_%s_%ld.csv",
                                 stats_dir_env, name, (long)getpid());
                if (n > 0 && n < (int)sizeof(path)) {
                        stats->out = fopen(path, "a");
                        if (stats->out != NULL) {
                                stats->file_output = 1;
                                setvbuf(stats->out, NULL, _IOLBF, 0);
                                if (ftell(stats->out) == 0) {
                                        fprintf(stats->out,
                                                "timestamp,component,pid,packets,samples,"
                                                "period_samples,max_us,avg_us,min_us\n");
                                }
                        } else {
                                stats->out = NULL;
                        }
                }
        }

        stats->initialized = 1;
}

static inline void
onvm_perf_sampler_init(struct onvm_perf_sampler *sampler) {
        if (sampler->initialized)
                return;

        sampler->sample_rate = onvm_perf_get_sample_rate();
        sampler->initialized = 1;
}

static inline uint64_t *
onvm_perf_trace_field(struct rte_mbuf *pkt, int trace_offset) {
        if (pkt == NULL || trace_offset < 0)
                return NULL;

        return (uint64_t *)((char *)pkt + trace_offset);
}

static inline void
onvm_perf_trace_start(struct onvm_perf_sampler *sampler, struct rte_mbuf *pkt,
                      int trace_offset) {
        uint64_t *trace_cycles = onvm_perf_trace_field(pkt, trace_offset);
        if (trace_cycles == NULL)
                return;

        onvm_perf_sampler_init(sampler);
        *trace_cycles = 0;

        if (sampler->sample_rate == 0)
                return;

        sampler->countdown++;
        if (sampler->countdown < sampler->sample_rate)
                return;

        sampler->countdown = 0;
        *trace_cycles = ONVM_PERF_TRACE_MARKER;
}

static inline void
onvm_perf_trace_stamp(struct rte_mbuf *pkt, int trace_offset) {
        uint64_t *trace_cycles = onvm_perf_trace_field(pkt, trace_offset);
        if (trace_cycles != NULL && *trace_cycles != 0)
                *trace_cycles = rte_get_tsc_cycles();
}

static inline uint64_t
onvm_perf_sample_begin(struct onvm_perf_stats *stats, const char *name) {
        onvm_perf_init(stats, name);
        stats->packets++;

        if (stats->sample_rate == 0)
                return 0;

        stats->countdown++;
        if (stats->countdown < stats->sample_rate)
                return 0;

        stats->countdown = 0;
        return rte_get_tsc_cycles();
}

static inline uint64_t
onvm_perf_sample_batch_begin(struct onvm_perf_stats *stats, const char *name,
                             uint16_t packet_count) {
        uint64_t old_bucket;
        uint64_t new_bucket;

        if (packet_count == 0)
                return 0;

        onvm_perf_init(stats, name);
        if (stats->sample_rate == 0) {
                stats->packets += packet_count;
                return 0;
        }

        old_bucket = stats->packets / stats->sample_rate;
        stats->packets += packet_count;
        new_bucket = stats->packets / stats->sample_rate;

        if (old_bucket == new_bucket)
                return 0;

        return rte_get_tsc_cycles();
}

static inline void
onvm_perf_print_if_due(struct onvm_perf_stats *stats, uint64_t now_cycles) {
        uint64_t hz = rte_get_timer_hz();
        double max_us;
        double avg_us;
        double min_us;

        if (stats->period_samples == 0 ||
            now_cycles - stats->last_print_cycles < hz * ONVM_PERF_PRINT_INTERVAL_SEC)
                return;

        max_us = (double)stats->period_max_cycles * 1000000.0 / (double)hz;
        avg_us = (double)stats->period_total_cycles * 1000000.0 /
            ((double)hz * (double)stats->period_samples);
        min_us = (double)stats->period_min_cycles * 1000000.0 / (double)hz;

        if (stats->file_output && stats->out != NULL) {
                char timestamp[20];
                time_t raw_time = time(NULL);
                struct tm local_time;
                if (localtime_r(&raw_time, &local_time) != NULL &&
                    strftime(timestamp, sizeof(timestamp), "%F %T", &local_time) > 0) {
                        fprintf(stats->out,
                                "%s,%s,%ld,%" PRIu64 ",%" PRIu64 ",%" PRIu64
                                ",%.3f,%.3f,%.3f\n",
                                timestamp, stats->name, (long)getpid(), stats->packets,
                                stats->samples, stats->period_samples,
                                max_us, avg_us, min_us);
                }
                fflush(stats->out);
        }

        stats->period_samples = 0;
        stats->period_total_cycles = 0;
        stats->period_min_cycles = UINT64_MAX;
        stats->period_max_cycles = 0;
        stats->last_print_cycles = now_cycles;
}

static inline void
onvm_perf_sample_end(struct onvm_perf_stats *stats, uint64_t start_cycles) {
        uint64_t now_cycles;
        uint64_t delta;

        if (start_cycles == 0)
                return;

        now_cycles = rte_get_tsc_cycles();
        delta = now_cycles - start_cycles;

        stats->samples++;
        stats->total_cycles += delta;
        if (delta < stats->min_cycles)
                stats->min_cycles = delta;
        if (delta > stats->max_cycles)
                stats->max_cycles = delta;

        stats->period_samples++;
        stats->period_total_cycles += delta;
        if (delta < stats->period_min_cycles)
                stats->period_min_cycles = delta;
        if (delta > stats->period_max_cycles)
                stats->period_max_cycles = delta;

        onvm_perf_print_if_due(stats, now_cycles);
}

static inline void
onvm_perf_sample_batch_end(struct onvm_perf_stats *stats, uint64_t start_cycles,
                           uint16_t packet_count) {
        uint64_t now_cycles;
        uint64_t delta;

        if (start_cycles == 0 || packet_count == 0)
                return;

        now_cycles = rte_get_tsc_cycles();
        delta = (now_cycles - start_cycles) / packet_count;
        if (delta == 0)
                delta = 1;

        stats->samples++;
        stats->total_cycles += delta;
        if (delta < stats->min_cycles)
                stats->min_cycles = delta;
        if (delta > stats->max_cycles)
                stats->max_cycles = delta;

        stats->period_samples++;
        stats->period_total_cycles += delta;
        if (delta < stats->period_min_cycles)
                stats->period_min_cycles = delta;
        if (delta > stats->period_max_cycles)
                stats->period_max_cycles = delta;

        onvm_perf_print_if_due(stats, now_cycles);
}

static inline void
onvm_perf_trace_record(struct onvm_perf_stats *stats, const char *name,
                       struct rte_mbuf *pkt, int trace_offset) {
        uint64_t now_cycles;
        uint64_t delta;
        uint64_t *trace_cycles;

        onvm_perf_init(stats, name);
        stats->packets++;

        trace_cycles = onvm_perf_trace_field(pkt, trace_offset);
        if (trace_cycles == NULL || *trace_cycles == 0 ||
            *trace_cycles == ONVM_PERF_TRACE_MARKER)
                return;

        now_cycles = rte_get_tsc_cycles();
        delta = now_cycles - *trace_cycles;

        stats->samples++;
        stats->total_cycles += delta;
        if (delta < stats->min_cycles)
                stats->min_cycles = delta;
        if (delta > stats->max_cycles)
                stats->max_cycles = delta;

        stats->period_samples++;
        stats->period_total_cycles += delta;
        if (delta < stats->period_min_cycles)
                stats->period_min_cycles = delta;
        if (delta > stats->period_max_cycles)
                stats->period_max_cycles = delta;

        *trace_cycles = ONVM_PERF_TRACE_MARKER;
        onvm_perf_print_if_due(stats, now_cycles);
}

#endif
