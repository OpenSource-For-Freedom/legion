/*
 * agent.c – Legion SIEM cross-platform system telemetry agent
 *
 * Compile:
 *   Linux:   gcc -O2 -Wall -I../include -o legion-agent agent.c
 *   macOS:   clang -O2 -Wall -I../include -o legion-agent agent.c
 *   Windows: cl /O2 /W3 /I..\include agent.c /link psapi.lib /Fe:legion-agent.exe
 *
 * Usage:
 *   legion-agent stats       -- print telemetry JSON
 *   legion-agent connections -- print active TCP connections JSON
 *   legion-agent all         -- print both (default)
 */

/* Feature-test macros – must come before ALL system headers.
 * _GNU_SOURCE on Linux   : exposes all POSIX + GNU APIs (usleep, getloadavg …)
 * _DARWIN_C_SOURCE on macOS: exposes getloadavg, popen, etc. */
#ifdef __linux__
#  define _GNU_SOURCE
#elif defined(__APPLE__)
#  define _DARWIN_C_SOURCE
#elif !defined(_WIN32)
#  define _POSIX_C_SOURCE 200809L
#endif

#include "agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Platform headers ───────────────────────────────────────────────────── */

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <psapi.h>
    #include <iphlpapi.h>
    #include <winsock2.h>
    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#elif defined(__APPLE__)
    #include <sys/sysctl.h>
    #include <sys/types.h>
    #include <mach/mach.h>
    #include <mach/mach_host.h>
    #include <unistd.h>
    #include <ifaddrs.h>
    #include <net/if.h>
#else
    /* Linux */
    #include <sys/sysinfo.h>
    #include <sys/utsname.h>
    #include <unistd.h>
    #include <dirent.h>
    #include <fcntl.h>
    #include <limits.h>
#endif

/* ── Utility: ISO-8601 UTC timestamp ────────────────────────────────────── */

static void utc_now(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm *tm_info;
#ifdef _WIN32
    struct tm gmt;
    gmtime_s(&gmt, &t);
    tm_info = &gmt;
#else
    tm_info = gmtime(&t);
#endif
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

/* ── Hostname ───────────────────────────────────────────────────────────── */

static void get_hostname(char *buf, size_t n) {
#ifdef _WIN32
    DWORD sz = (DWORD)n;
    if (!GetComputerNameA(buf, &sz)) strncpy(buf, "unknown", n);
#else
    if (gethostname(buf, n) != 0) strncpy(buf, "unknown", n);
#endif
    buf[n - 1] = '\0';
}

/* ═════════════════════════════════════════════════════════════════════════ */
/*  Windows implementation                                                   */
/* ═════════════════════════════════════════════════════════════════════════ */
#ifdef _WIN32

static float cpu_pct_windows(void) {
    /* Two-sample difference of idle/kernel/user counters */
    FILETIME idle1, kern1, user1, idle2, kern2, user2;
    if (!GetSystemTimes(&idle1, &kern1, &user1)) return 0.0f;
    Sleep(200);
    if (!GetSystemTimes(&idle2, &kern2, &user2)) return 0.0f;

    auto to_u64 = [](FILETIME ft) -> uint64_t {
        return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    };
    uint64_t idle_diff = to_u64(idle2) - to_u64(idle1);
    uint64_t kern_diff = to_u64(kern2) - to_u64(kern1);
    uint64_t user_diff = to_u64(user2) - to_u64(user1);
    uint64_t total = kern_diff + user_diff;
    if (total == 0) return 0.0f;
    return (float)(total - idle_diff) / (float)total * 100.0f;
}

/* Pure C99 version without lambda */
static uint64_t ft_to_u64(FILETIME ft) {
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

static float cpu_pct_win_c99(void) {
    FILETIME idle1, kern1, user1, idle2, kern2, user2;
    if (!GetSystemTimes(&idle1, &kern1, &user1)) return 0.0f;
    Sleep(200);
    if (!GetSystemTimes(&idle2, &kern2, &user2)) return 0.0f;
    uint64_t idle_d = ft_to_u64(idle2) - ft_to_u64(idle1);
    uint64_t kern_d = ft_to_u64(kern2) - ft_to_u64(kern1);
    uint64_t user_d = ft_to_u64(user2) - ft_to_u64(user1);
    uint64_t total  = kern_d + user_d;
    if (total == 0) return 0.0f;
    return (float)(total - idle_d) / (float)total * 100.0f;
}

int legion_collect(legion_stats_t *s) {
    memset(s, 0, sizeof(*s));
    utc_now(s->sampled_at, sizeof(s->sampled_at));
    get_hostname(s->hostname, sizeof(s->hostname));
    strncpy(s->os_name, "Windows", sizeof(s->os_name) - 1);

    s->cpu_pct = cpu_pct_win_c99();

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        s->mem_total_kb = ms.ullTotalPhys / 1024;
        s->mem_used_kb  = (ms.ullTotalPhys - ms.ullAvailPhys) / 1024;
    }

    /* Process count via snapshot */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do { s->proc_count++; } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    s->load_avg_1 = 0.0; /* Not available on Windows */
    return 0;
}

int legion_connections(legion_conn_t *conns, int max_conns) {
    DWORD sz = 0;
    GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)malloc(sz);
    if (!table) return -1;

    int count = 0;
    if (GetExtendedTcpTable(table, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries && count < max_conns; i++) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            if (row->dwState == MIB_TCP_STATE_ESTAB) {
                struct in_addr addr;
                addr.s_addr = row->dwRemoteAddr;
                strncpy(conns[count].remote_ip, inet_ntoa(addr), sizeof(conns[count].remote_ip) - 1);
                conns[count].remote_port = ntohs((u_short)row->dwRemotePort);
                strncpy(conns[count].state, "ESTABLISHED", sizeof(conns[count].state) - 1);
                count++;
            }
        }
    }
    free(table);
    return count;
}

/* ═════════════════════════════════════════════════════════════════════════ */
/*  macOS implementation                                                     */
/* ═════════════════════════════════════════════════════════════════════════ */
#elif defined(__APPLE__)

int legion_collect(legion_stats_t *s) {
    memset(s, 0, sizeof(*s));
    utc_now(s->sampled_at, sizeof(s->sampled_at));
    get_hostname(s->hostname, sizeof(s->hostname));
    strncpy(s->os_name, "macOS", sizeof(s->os_name) - 1);

    /* CPU via host_statistics */
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t info1, info2;
    host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                    (host_info_t)&info1, &count);
    usleep(200000);
    count = HOST_CPU_LOAD_INFO_COUNT;
    host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                    (host_info_t)&info2, &count);
    natural_t idle_d = info2.cpu_ticks[CPU_STATE_IDLE]  - info1.cpu_ticks[CPU_STATE_IDLE];
    natural_t user_d = info2.cpu_ticks[CPU_STATE_USER]  - info1.cpu_ticks[CPU_STATE_USER];
    natural_t sys_d  = info2.cpu_ticks[CPU_STATE_SYSTEM]- info1.cpu_ticks[CPU_STATE_SYSTEM];
    natural_t nice_d = info2.cpu_ticks[CPU_STATE_NICE]  - info1.cpu_ticks[CPU_STATE_NICE];
    natural_t total  = idle_d + user_d + sys_d + nice_d;
    s->cpu_pct = total > 0 ? (float)(total - idle_d) / (float)total * 100.0f : 0.0f;

    /* Memory */
    int mib[2] = {CTL_HW, HW_MEMSIZE};
    uint64_t total_mem;
    size_t sz = sizeof(total_mem);
    sysctl(mib, 2, &total_mem, &sz, NULL, 0);
    s->mem_total_kb = total_mem / 1024;

    mach_port_t host = mach_host_self();
    vm_size_t page_size;
    host_page_size(host, &page_size);
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t vcnt = HOST_VM_INFO64_COUNT;
    host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vm_stat, &vcnt);
    uint64_t used = ((uint64_t)(vm_stat.active_count + vm_stat.wire_count)) * page_size;
    s->mem_used_kb = used / 1024;

    /* Process count */
    int nproc = 0;
    size_t len = sizeof(nproc);
    int mib2[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    if (sysctl(mib2, 3, NULL, &len, NULL, 0) == 0)
        s->proc_count = (uint32_t)(len / sizeof(struct kinfo_proc));

    /* Load average */
    double load[3] = {0};
    getloadavg(load, 3);
    s->load_avg_1 = load[0];

    return 0;
}

int legion_connections(legion_conn_t *conns, int max_conns) {
    /* On macOS use netstat via popen */
    FILE *f = popen("netstat -tn 2>/dev/null | grep ESTABLISHED", "r");
    if (!f) return -1;
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && count < max_conns) {
        char proto[8], local[64], remote[64], state[32];
        if (sscanf(line, "%7s %*s %*s %63s %63s %31s", proto, local, remote, state) >= 3) {
            /* strip port from remote: last '.' separates ip.port */
            char *dot = strrchr(remote, '.');
            if (dot) {
                *dot = '\0';
                conns[count].remote_port = (uint16_t)atoi(dot + 1);
            }
            strncpy(conns[count].remote_ip, remote, sizeof(conns[count].remote_ip) - 1);
            strncpy(conns[count].state, "ESTABLISHED", sizeof(conns[count].state) - 1);
            count++;
        }
    }
    pclose(f);
    return count;
}

/* ═════════════════════════════════════════════════════════════════════════ */
/*  Linux implementation                                                     */
/* ═════════════════════════════════════════════════════════════════════════ */
#else

static float cpu_pct_linux(void) {
    /* Read /proc/stat twice to get delta */
    unsigned long u1, n1, s1, i1, u2, n2, s2, i2;
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0.0f;
    if (fscanf(f, "cpu %lu %lu %lu %lu", &u1, &n1, &s1, &i1) != 4) {
        fclose(f); return 0.0f;
    }
    fclose(f);
    usleep(200000);
    f = fopen("/proc/stat", "r");
    if (!f) return 0.0f;
    if (fscanf(f, "cpu %lu %lu %lu %lu", &u2, &n2, &s2, &i2) != 4) {
        fclose(f); return 0.0f;
    }
    fclose(f);
    unsigned long idle_d  = i2 - i1;
    unsigned long total_d = (u2+n2+s2+i2) - (u1+n1+s1+i1);
    if (total_d == 0) return 0.0f;
    return (float)(total_d - idle_d) / (float)total_d * 100.0f;
}

static uint32_t count_procs_linux(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *ent;
    uint32_t n = 0;
    while ((ent = readdir(d)) != NULL) {
        char *end;
        strtol(ent->d_name, &end, 10);
        if (*end == '\0') n++;
    }
    closedir(d);
    return n;
}

int legion_collect(legion_stats_t *s) {
    memset(s, 0, sizeof(*s));
    utc_now(s->sampled_at, sizeof(s->sampled_at));
    get_hostname(s->hostname, sizeof(s->hostname));

    /* OS name from /etc/os-release or uname */
    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(s->os_name, sizeof(s->os_name), "Linux/%s", uts.release);
    else
        strncpy(s->os_name, "Linux", sizeof(s->os_name) - 1);

    s->cpu_pct = cpu_pct_linux();

    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        s->mem_total_kb = (uint64_t)si.totalram * si.mem_unit / 1024;
        s->mem_used_kb  = (uint64_t)(si.totalram - si.freeram) * si.mem_unit / 1024;
    }

    s->proc_count = count_procs_linux();

    double load[3] = {0};
    getloadavg(load, 3);
    s->load_avg_1 = load[0];

    return 0;
}

int legion_connections(legion_conn_t *conns, int max_conns) {
    /* Parse /proc/net/tcp – hex encoded */
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return -1;
    char line[256];
    if (!fgets(line, sizeof(line), f)) { /* skip header */
        fclose(f);
        return 0;
    }
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max_conns) {
        unsigned int sl, local_addr, rem_addr, state;
        unsigned int local_port, rem_port;
        if (sscanf(line, " %u: %X:%X %X:%X %X",
                   &sl, &local_addr, &local_port, &rem_addr, &rem_port, &state) == 6) {
            if (state == 0x01) { /* TCP_ESTABLISHED */
                /* Convert from little-endian hex */
                unsigned char *b = (unsigned char *)&rem_addr;
                snprintf(conns[count].remote_ip, sizeof(conns[count].remote_ip),
                         "%u.%u.%u.%u", b[3], b[2], b[1], b[0]);
                conns[count].remote_port = (uint16_t)rem_port;
                strncpy(conns[count].state, "ESTABLISHED", sizeof(conns[count].state) - 1);
                /* Skip loopback */
                if (strncmp(conns[count].remote_ip, "127.", 4) != 0 &&
                    strncmp(conns[count].remote_ip, "0.0.", 4) != 0) {
                    count++;
                }
            }
        }
    }
    fclose(f);
    return count;
}

#endif /* platform */

/* ═════════════════════════════════════════════════════════════════════════ */
/*  JSON output (platform-independent)                                       */
/* ═════════════════════════════════════════════════════════════════════════ */

void legion_print_json(const legion_stats_t *s) {
    printf("{\n"
           "  \"cpu_pct\":      %.2f,\n"
           "  \"mem_used_kb\":  %llu,\n"
           "  \"mem_total_kb\": %llu,\n"
           "  \"proc_count\":   %u,\n"
           "  \"net_rx_bytes\": %llu,\n"
           "  \"net_tx_bytes\": %llu,\n"
           "  \"load_avg_1\":   %.2f,\n"
           "  \"hostname\":     \"%s\",\n"
           "  \"os_name\":      \"%s\",\n"
           "  \"sampled_at\":   \"%s\"\n"
           "}\n",
           s->cpu_pct,
           (unsigned long long)s->mem_used_kb,
           (unsigned long long)s->mem_total_kb,
           s->proc_count,
           (unsigned long long)s->net_rx_bytes,
           (unsigned long long)s->net_tx_bytes,
           s->load_avg_1,
           s->hostname,
           s->os_name,
           s->sampled_at);
}

void legion_print_conns_json(const legion_conn_t *conns, int count) {
    printf("[\n");
    for (int i = 0; i < count; i++) {
        printf("  {\"ip\": \"%s\", \"port\": %u, \"state\": \"%s\"}%s\n",
               conns[i].remote_ip,
               conns[i].remote_port,
               conns[i].state,
               i + 1 < count ? "," : "");
    }
    printf("]\n");
}

/* ═════════════════════════════════════════════════════════════════════════ */
/*  main                                                                     */
/* ═════════════════════════════════════════════════════════════════════════ */

/* Define LEGION_NO_MAIN when linking agent.c into a test harness that supplies
 * its own main() (see tests/test_agent.c). */
#ifndef LEGION_NO_MAIN
int main(int argc, char *argv[]) {
    const char *mode = (argc > 1) ? argv[1] : "all";

    if (strcmp(mode, "stats") == 0 || strcmp(mode, "all") == 0) {
        legion_stats_t stats;
        if (legion_collect(&stats) == 0) {
            legion_print_json(&stats);
        } else {
            fprintf(stderr, "legion-agent: failed to collect stats\n");
            return 1;
        }
    }

    if (strcmp(mode, "connections") == 0 || strcmp(mode, "all") == 0) {
        legion_conn_t conns[1024];
        int n = legion_connections(conns, 1024);
        if (n >= 0) {
            legion_print_conns_json(conns, n);
        }
    }

    return 0;
}
#endif /* LEGION_NO_MAIN */
