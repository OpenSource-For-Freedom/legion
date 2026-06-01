//! Legion TUI – ratatui rendering layer.

use crate::app::App;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

// ─────────────────────────────── Colours ────────────────────────────────────

const CRIT_COLOR:   Color = Color::Red;
const HIGH_COLOR:   Color = Color::LightRed;
const MED_COLOR:    Color = Color::Yellow;
const BORDER_COLOR: Color = Color::DarkGray;
const HEADER_BG:    Color = Color::Rgb(20, 20, 40);
const SEL_BG:       Color = Color::Rgb(40, 40, 80);
const DIM:          Color = Color::DarkGray;
const ACCENT:       Color = Color::LightCyan;
const LABEL:        Color = Color::Rgb(80, 100, 130);

fn severity_color(label: &str) -> Color {
    match label.trim() {
        "CRIT" => CRIT_COLOR,
        "HIGH" => HIGH_COLOR,
        "MED " | "MED" => MED_COLOR,
        "LOW " | "LOW" => Color::Cyan,
        _ => Color::Green,
    }
}

// ─────────────────────────────── Entry Point ────────────────────────────────

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let outer = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .split(area);
    render_header(f, outer[0], app);
    render_body(f, outer[1], app);
    render_footer(f, outer[2], app);
}

// ─────────────────────────────── Header ─────────────────────────────────────

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let alert_count = app.alerts.len();
    let crit_count = app.alerts.iter()
        .filter(|a| matches!(a.severity, legion_core::alerts::Severity::Critical))
        .count();
    let ip_count = app.feed_info.active_connections.len();

    let alert_label = if alert_count == 0 {
        "● CLEAR".to_owned()
    } else {
        format!("▲ {} ALERT{}  {} CRIT", alert_count, if alert_count == 1 { "" } else { "S" }, crit_count)
    };
    let alert_color = if alert_count == 0 { Color::Green } else { CRIT_COLOR };

    let conn_span = if ip_count > 0 {
        Span::styled(format!("⚠ {} ACTIVE CONN", ip_count), Style::default().fg(Color::Yellow))
    } else {
        Span::styled("⬡ CONNECTIONS CLEAR", Style::default().fg(DIM))
    };
    let qua_span = if app.feed_info.quarantine_count > 0 {
        Span::styled(format!("⚑ {} QUARANTINED", app.feed_info.quarantine_count), Style::default().fg(Color::LightRed))
    } else {
        Span::styled("⚑ QUARANTINE CLEAR", Style::default().fg(DIM))
    };

    let title = Line::from(vec![
        Span::styled(" LEGION ", Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" SIEM / SOAR  ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(now, Style::default().fg(DIM)),
        Span::raw("   "),
        Span::styled(alert_label, Style::default().fg(alert_color).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        conn_span,
        Span::raw("   "),
        qua_span,
    ]);

    f.render_widget(
        Paragraph::new(title).block(
            Block::default().borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR))
                .style(Style::default().bg(HEADER_BG)),
        ),
        area,
    );
}

// ─────────────────────────────── Body ───────────────────────────────────────

fn render_body(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).split(area);

    // Left: alerts table + optional detail pane
    let show_detail = app.table_state.selected().is_some() && !app.alerts.is_empty();
    let left = if show_detail {
        Layout::vertical([Constraint::Min(0), Constraint::Length(6)]).split(cols[0])
    } else {
        Layout::vertical([Constraint::Min(0), Constraint::Length(0)]).split(cols[0])
    };
    render_alerts_table(f, left[0], app);
    if show_detail {
        render_alert_detail(f, left[1], app);
    }

    // Right: stacked panels
    let right = Layout::vertical([
        Constraint::Length(9),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Min(4),
    ])
    .split(cols[1]);
    render_telemetry(f, right[0], app);
    render_feed_info(f, right[1], app);
    render_scan_status(f, right[2], app);
    render_connections(f, right[3], app);
}

// ─────────────────────────────── Alerts Table ───────────────────────────────

fn render_alerts_table(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(
        ["ID", "SEV ", "TYPE            ", "TITLE", "PACKAGE"].iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
    )
    .style(Style::default().bg(Color::Rgb(30, 30, 60)))
    .height(1);

    let all_rows: Vec<Row> = if app.alerts.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(" ● No active alerts — system clear").style(Style::default().fg(Color::Green)),
            Cell::from(""),
        ])]
    } else {
        app.alerts.iter().map(|a| {
            let sev_label = a.severity.label();
            let sev_color = severity_color(sev_label);
            let pkg = a.package_name.as_deref().unwrap_or("—");
            Row::new(vec![
                Cell::from(a.id.to_string()),
                Cell::from(sev_label).style(Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Cell::from(a.kind_str()),
                Cell::from(truncate(&a.title, 34)),
                Cell::from(truncate(pkg, 20)).style(Style::default().fg(ACCENT)),
            ])
        }).collect()
    };

    let table = Table::new(
        all_rows,
        [
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(16),
            Constraint::Fill(1),
            Constraint::Length(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" ACTIVE ALERTS ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER_COLOR)),
    )
    .highlight_style(Style::default().bg(SEL_BG).add_modifier(Modifier::BOLD))
    .highlight_symbol("► ");

    let mut state = app.table_state.clone();
    f.render_stateful_widget(table, area, &mut state);
}

// ─────────────────────────────── Alert Detail ───────────────────────────────

fn render_alert_detail(f: &mut Frame, area: Rect, app: &App) {
    let lines = if let Some(a) = app.table_state.selected().and_then(|i| app.alerts.get(i)) {
        let cves = if a.cve_ids.is_empty() { "—".to_owned() } else { a.cve_ids.join(", ") };
        let ip  = a.ip_address.as_deref().unwrap_or("—");
        let eco = a.package_ecosystem.as_deref().unwrap_or("—");
        let pkg = a.package_name.as_deref().unwrap_or("—");
        vec![
            Line::from(vec![
                Span::styled(" Package: ", Style::default().fg(LABEL)),
                Span::styled(format!("{pkg} ({eco})"), Style::default().fg(ACCENT)),
                Span::styled("   CVEs: ", Style::default().fg(LABEL)),
                Span::styled(cves, Style::default().fg(MED_COLOR)),
            ]),
            Line::from(vec![
                Span::styled(" IP:      ", Style::default().fg(LABEL)),
                Span::styled(ip.to_string(), Style::default().fg(HIGH_COLOR)),
                Span::styled("   Time: ", Style::default().fg(LABEL)),
                Span::raw(a.created_at[..19.min(a.created_at.len())].to_string()),
            ]),
            Line::from(vec![
                Span::styled(" Detail:  ", Style::default().fg(LABEL)),
                Span::raw(truncate(&a.detail, 90)),
            ]),
        ]
    } else {
        vec![]
    };

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default().title(" ALERT DETAIL ").borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 100))),
        ),
        area,
    );
}

// ─────────────────────────────── Telemetry ──────────────────────────────────

fn render_telemetry(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.stats;
    let mem_pct = s.mem_pct();
    let lines = vec![
        gauge_line("CPU ", s.cpu_pct, Color::LightMagenta),
        gauge_line("MEM ", mem_pct, Color::LightBlue),
        Line::from(vec![
            Span::styled(" PRCS  ", Style::default().fg(LABEL)),
            Span::styled(format!("{:<8}", s.proc_count), Style::default().fg(Color::White)),
            Span::styled("LOAD  ", Style::default().fg(LABEL)),
            Span::styled(format!("{:.2}", s.load_avg_1), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" NET↑  ", Style::default().fg(LABEL)),
            Span::styled(fmt_kb(s.net_tx_kb), Style::default().fg(Color::LightGreen)),
            Span::styled("   NET↓  ", Style::default().fg(LABEL)),
            Span::styled(fmt_kb(s.net_rx_kb), Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            Span::styled(" RAM   ", Style::default().fg(LABEL)),
            Span::styled(fmt_mb(s.mem_used_mb), Style::default().fg(ACCENT)),
            Span::styled(" / ", Style::default().fg(DIM)),
            Span::styled(fmt_mb(s.mem_total_mb), Style::default().fg(DIM)),
        ]),
        Line::from(vec![
            Span::styled(" CONN  ", Style::default().fg(LABEL)),
            Span::styled(
                app.feed_info.active_connections.len().to_string(),
                Style::default().fg(if app.feed_info.active_connections.is_empty() { Color::Green } else { Color::Yellow }),
            ),
            Span::styled(" active remote IPs", Style::default().fg(DIM)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default().title(" SYSTEM TELEMETRY ").borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR)),
        ),
        area,
    );
}

fn gauge_line(label: &str, pct: f32, color: Color) -> Line<'static> {
    let bar_total = 18usize;
    let filled = ((pct / 100.0) * bar_total as f32).round() as usize;
    let bar = format!("{}{}", "█".repeat(filled.min(bar_total)), "░".repeat(bar_total - filled.min(bar_total)));
    Line::from(vec![
        Span::styled(format!(" {label}"), Style::default().fg(LABEL)),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(format!(" {:.0}%", pct), Style::default().fg(Color::White)),
    ])
}

// ─────────────────────────────── Threat Feeds ───────────────────────────────

fn render_feed_info(f: &mut Frame, area: Rect, app: &App) {
    let fi = &app.feed_info;
    let lines = vec![
        Line::from(vec![
            Span::styled(" Events Cached   ", Style::default().fg(LABEL)),
            Span::styled(fi.events_cached.to_string(),
                Style::default().fg(if fi.events_cached > 0 { ACCENT } else { DIM }).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(" IPs Blacklisted ", Style::default().fg(LABEL)),
            Span::styled(fi.ips_cached.to_string(),
                Style::default().fg(if fi.ips_cached > 0 { Color::LightRed } else { DIM }).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(" Quarantined Pkgs", Style::default().fg(LABEL)),
            Span::styled(fi.quarantine_count.to_string(),
                Style::default().fg(if fi.quarantine_count > 0 { Color::LightRed } else { Color::Green }).add_modifier(Modifier::BOLD)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default().title(" THREAT FEEDS ").borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR)),
        ),
        area,
    );
}

// ─────────────────────────────── Scan Status ────────────────────────────────

fn render_scan_status(f: &mut Frame, area: Rect, app: &App) {
    let si = &app.scan_info;
    let total = si.cargo_count + si.npm_count + si.pip_count;
    let lines = vec![
        Line::from(vec![
            Span::styled(" Last     ", Style::default().fg(LABEL)),
            Span::styled(si.last_scan.as_deref().unwrap_or("never").to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Total    ", Style::default().fg(LABEL)),
            Span::styled(format!("{total} packages"), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(" Cargo    ", Style::default().fg(Color::Yellow)),
            Span::styled(format!("{}", si.cargo_count), Style::default().fg(Color::White)),
            Span::styled("  npm  ", Style::default().fg(Color::Green)),
            Span::styled(format!("{}", si.npm_count), Style::default().fg(Color::White)),
            Span::styled("  pip  ", Style::default().fg(ACCENT)),
            Span::styled(format!("{}", si.pip_count), Style::default().fg(Color::White)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default().title(" SCAN STATUS ").borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR)),
        ),
        area,
    );
}

// ─────────────────────────────── Active Connections ─────────────────────────

fn render_connections(f: &mut Frame, area: Rect, app: &App) {
    let conns = &app.feed_info.active_connections;
    let lines: Vec<Line> = if conns.is_empty() {
        vec![Line::from(Span::styled(" ● No active remote connections", Style::default().fg(Color::Green)))]
    } else {
        conns.iter().take(area.height.saturating_sub(2) as usize).map(|ip| {
            let blacklisted = app.alerts.iter().any(|a| a.ip_address.as_deref() == Some(ip.as_str()));
            if blacklisted {
                Line::from(vec![
                    Span::styled(" ⚠ ", Style::default().fg(Color::Red)),
                    Span::styled(ip.clone(), Style::default().fg(Color::Red)),
                    Span::styled(" BLACKLISTED", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" · ", Style::default().fg(DIM)),
                    Span::styled(ip.clone(), Style::default().fg(DIM)),
                ])
            }
        }).collect()
    };
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default().title(" ACTIVE CONNECTIONS ").borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR)),
        ),
        area,
    );
}

// ─────────────────────────────── Footer ─────────────────────────────────────

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let status = app.status_msg.as_deref().unwrap_or("");
    let line = Line::from(vec![
        Span::styled(" [R] ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::raw("Refresh  "),
        Span::styled("[S] ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Span::raw("Scan  "),
        Span::styled("[A] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("Ack  "),
        Span::styled("[↑↓] ", Style::default().fg(Color::White)),
        Span::raw("Navigate  "),
        Span::styled("[q] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("Quit"),
        Span::styled("    ", Style::default()),
        Span::styled(status.to_string(), Style::default().fg(DIM)),
    ]);
    f.render_widget(
        Paragraph::new(line).block(
            Block::default().borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_COLOR)),
        ),
        area,
    );
}

// ─────────────────────────────── Utils ──────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_owned() } else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

fn fmt_kb(kb: u64) -> String {
    if kb < 1024 { format!("{kb} KB/s") } else { format!("{:.1} MB/s", kb as f64 / 1024.0) }
}

fn fmt_mb(mb: u64) -> String {
    if mb < 1024 { format!("{mb} MB") } else { format!("{:.1} GB", mb as f64 / 1024.0) }
}
