/*
 * legion_agent.h – Legion SIEM system telemetry C agent
 * Cross-platform: Windows, Linux, macOS
 * Outputs JSON to stdout.
 *
 * Build: see ../Makefile
 */

#ifndef LEGION_AGENT_H
#define LEGION_AGENT_H

#include <stdint.h>

/* ── Telemetry snapshot ─────────────────────────────────────────────────── */

typedef struct {
    float    cpu_pct;         /* 0.0–100.0 */
    uint64_t mem_used_kb;
    uint64_t mem_total_kb;
    uint32_t proc_count;
    uint64_t net_rx_bytes;
    uint64_t net_tx_bytes;
    double   load_avg_1;      /* 0.0 on Windows */
    char     hostname[256];
    char     os_name[128];
    char     sampled_at[32];  /* ISO-8601 UTC */
} legion_stats_t;

/* ── Active TCP connection ──────────────────────────────────────────────── */

typedef struct {
    char     remote_ip[64];
    uint16_t remote_port;
    char     state[32];
} legion_conn_t;

/* ── API ────────────────────────────────────────────────────────────────── */

/**
 * Collect a telemetry snapshot into *stats.
 * Returns 0 on success, -1 on error.
 */
int legion_collect(legion_stats_t *stats);

/**
 * Collect active TCP connections into *conns (caller allocates max_conns entries).
 * Returns number of connections written, or -1 on error.
 */
int legion_connections(legion_conn_t *conns, int max_conns);

/**
 * Print telemetry JSON to stdout.
 */
void legion_print_json(const legion_stats_t *stats);

/**
 * Print connections JSON array to stdout.
 */
void legion_print_conns_json(const legion_conn_t *conns, int count);

#endif /* LEGION_AGENT_H */
