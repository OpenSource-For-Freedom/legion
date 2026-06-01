/*
 * test_agent.c – minimal unit tests for legion-agent
 * Compile: gcc -I../include -o test_agent test_agent.c ../src/agent.c
 * Run:     ./test_agent
 */

#include "../include/agent.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_passed++; printf("[PASS] %s\n", msg); } \
    else { printf("[FAIL] %s\n", msg); } \
} while (0)

/* ── Test: collect fills the struct ──────────────────────────────────────── */
static void test_collect_basic(void) {
    legion_stats_t s;
    int rc = legion_collect(&s);
    ASSERT(rc == 0,           "legion_collect returns 0");
    ASSERT(s.mem_total_kb > 0,"mem_total_kb > 0");
    ASSERT(s.cpu_pct >= 0.0f && s.cpu_pct <= 100.0f, "cpu_pct in [0,100]");
    ASSERT(strlen(s.hostname) > 0, "hostname not empty");
    ASSERT(strlen(s.sampled_at) > 0, "sampled_at not empty");
    ASSERT(s.proc_count > 0,  "proc_count > 0");
}

/* ── Test: connections returns non-negative ───────────────────────────────── */
static void test_connections(void) {
    legion_conn_t conns[256];
    int n = legion_connections(conns, 256);
    ASSERT(n >= 0, "legion_connections returns >= 0");
    printf("  (found %d established TCP connections)\n", n);
}

/* ── Test: JSON output doesn't crash ─────────────────────────────────────── */
static void test_json_output(void) {
    legion_stats_t s;
    legion_collect(&s);
    /* Redirect stdout check: just call and trust no crash */
    tests_run++;
    legion_print_json(&s);
    tests_passed++;
    printf("[PASS] legion_print_json (no crash)\n");
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== Legion Agent Tests ===\n");
    test_collect_basic();
    test_connections();
    test_json_output();
    printf("\n%d / %d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
