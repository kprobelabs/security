#![allow(deprecated)] // aya renames Bpf → Ebpf in newer versions

use aya::{include_bytes_aligned, Bpf, Btf};
use aya::maps::RingBuf;
use aya::programs::{
    BtfTracePoint, PerfEvent,
    perf_event::{HardwareEvent, PerfEventConfig, PerfEventScope, SamplePolicy},
};
use aya::util::online_cpus;
use spica_common::ProcessInfo;
use std::{
    collections::{HashMap, HashSet},
    fs,
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};

include!(concat!(env!("OUT_DIR"), "/keys.rs"));

const TICK_RATE_MS:           u64 = 100;
const SUSPECT_THRESHOLD_SECS: u64 = 2;
const GRACE_WINDOW_MS:        u64 = 50;
const ALERT_COOLDOWN_SECS:    u64 = 30;
const GHOST_THRESHOLD_SECS:   u64 = 5;
const SILENCE_THRESHOLD_SECS: u64 = 10;

// ── Data model ────────────────────────────────────────────────────────────────

struct AlertState {
    last_dkom:   Option<Instant>,
    last_tamper: Option<Instant>,
    last_ghost:  Option<Instant>,
}

struct ProcessRecord {
    start_time_ns:       u64,
    first_seen:          Instant,
    sched_last_seen:     Option<Instant>,
    nmi_last_seen:       Option<Instant>,
    dkom_suspect_since:  Option<Instant>,
    ghost_suspect_since: Option<Instant>,
    alerts:              AlertState,
}

type ProcessRegistry = HashMap<u32, ProcessRecord>;

enum Channel { Sched, Nmi }

// ── Detection logic ───────────────────────────────────────────────────────────

fn process_event(info: &ProcessInfo, registry: &mut ProcessRegistry, channel: Channel) {
    if info.tgid == 0 { return; }
    let now = Instant::now();

    let record = registry.entry(info.tgid).or_insert_with(|| ProcessRecord {
        start_time_ns:       info.start_time_ns,
        first_seen:          now,
        sched_last_seen:     None,
        nmi_last_seen:       None,
        dkom_suspect_since:  None,
        ghost_suspect_since: None,
        alerts: AlertState { last_dkom: None, last_tamper: None, last_ghost: None },
    });

    // Anchor start_time on first real event for seeded (start_time_ns = 0) entries.
    // On subsequent events, a mismatch means two structurally distinct processes
    // are claiming the same TGID — task_struct field spoofing.
    if record.start_time_ns == 0 && info.start_time_ns != 0 {
        record.start_time_ns = info.start_time_ns;
    } else if info.start_time_ns != 0 && record.start_time_ns != 0
           && record.start_time_ns != info.start_time_ns {
        println!("[DUPE]       tgid:{:<6} {:<16} task_struct spoofing suspected",
            info.tgid, resolve_comm(info.tgid));
    }

    match channel {
        Channel::Sched => record.sched_last_seen = Some(now),
        Channel::Nmi   => record.nmi_last_seen   = Some(now),
    }
}

fn run_detection(registry: &mut ProcessRegistry) {
    let user_tgids        = read_proc_tgids();
    let grace             = Duration::from_millis(GRACE_WINDOW_MS);
    let suspect_threshold = Duration::from_secs(SUSPECT_THRESHOLD_SECS);
    let ghost_threshold   = Duration::from_secs(GHOST_THRESHOLD_SECS);
    let cooldown          = Duration::from_secs(ALERT_COOLDOWN_SECS);
    let stale             = Duration::from_secs(10);
    let now               = Instant::now();

    // Ensure /proc-only TGIDs have a registry entry so GHOST tracking can start.
    for &tgid in &user_tgids {
        registry.entry(tgid).or_insert_with(|| ProcessRecord {
            start_time_ns:       0,
            first_seen:          now,
            sched_last_seen:     None,
            nmi_last_seen:       None,
            dkom_suspect_since:  None,
            ghost_suspect_since: None,
            alerts: AlertState { last_dkom: None, last_tamper: None, last_ghost: None },
        });
    }

    for (&tgid, record) in registry.iter_mut() {
        if record.first_seen.elapsed() < grace { continue; }

        let in_proc    = user_tgids.contains(&tgid);
        let sched_alive = record.sched_last_seen.map(|t| t.elapsed() < Duration::from_millis(500)).unwrap_or(false);
        let nmi_alive   = record.nmi_last_seen  .map(|t| t.elapsed() < Duration::from_millis(500)).unwrap_or(false);
        let ebpf_alive  = sched_alive || nmi_alive;

        // [TAMPER]: NMI has ever observed this TGID but sched_switch never has.
        if record.nmi_last_seen.is_some() && record.sched_last_seen.is_none() {
            let should_alert = record.alerts.last_tamper.map(|t| t.elapsed() > cooldown).unwrap_or(true);
            if should_alert {
                record.alerts.last_tamper = Some(now);
                println!("[TAMPER]     tgid:{:<6} {:<16} sched_switch suppressed", tgid, resolve_comm(tgid));
            }
        } else {
            record.alerts.last_tamper = None;
        }

        // [DKOM]: eBPF-active process absent from /proc.
        if !in_proc && ebpf_alive {
            let since = record.dkom_suspect_since.get_or_insert(now);
            if since.elapsed() > suspect_threshold {
                let should_alert = record.alerts.last_dkom.map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_dkom = Some(now);
                    println!("[DKOM]       tgid:{:<6} {:<16} hidden {:.1}s",
                        tgid, resolve_comm(tgid), since.elapsed().as_secs_f64());
                }
            }
        } else {
            record.dkom_suspect_since = None;
            record.alerts.last_dkom   = None;
        }

        // [GHOST]: in /proc but never observed by either eBPF channel.
        if in_proc && record.sched_last_seen.is_none() && record.nmi_last_seen.is_none() {
            let since = record.ghost_suspect_since.get_or_insert(now);
            if since.elapsed() > ghost_threshold {
                let should_alert = record.alerts.last_ghost.map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_ghost = Some(now);
                    println!("[GHOST]      tgid:{:<6} {:<16} present in /proc, never seen by eBPF",
                        tgid, resolve_comm(tgid));
                }
            }
        } else {
            record.ghost_suspect_since = None;
            record.alerts.last_ghost   = None;
        }
    }

    // Stale eviction: drop entries not recently active and no longer in /proc.
    registry.retain(|&tgid, record| {
        let sched_age = record.sched_last_seen.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
        let nmi_age   = record.nmi_last_seen  .map(|t| t.elapsed()).unwrap_or(Duration::MAX);
        sched_age < stale || nmi_age < stale || user_tgids.contains(&tgid)
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// ProcessInfo is defined in spica-common; inherent impl methods cannot be added
// from outside the defining crate, so deobfuscation lives here as a free function.
fn deobfuscate(raw: &ProcessInfo) -> ProcessInfo {
    let key = BASE_KEY ^ (raw.cpu as u64);
    ProcessInfo {
        pid:          raw.pid  ^ (key as u32),
        tgid:         raw.tgid ^ ((key >> 32) as u32),
        comm:         raw.comm,
        last_seen:    raw.last_seen,
        start_time_ns: raw.start_time_ns,
        cpu:          raw.cpu,
    }
}

fn read_proc_tgids() -> HashSet<u32> {
    let mut set = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(n) = entry.file_name().to_string_lossy().parse::<u32>() {
                set.insert(n);
            }
        }
    }
    set
}

fn resolve_comm(tgid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_else(|_| "???".into())
        .trim()
        .to_string()
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/spica")
    ))?;

    let btf = Btf::from_sys_fs()?;
    let sched_prog: &mut BtfTracePoint = bpf.program_mut("spica_sched").unwrap().try_into()?;
    sched_prog.load("sched_switch", &btf)?;
    sched_prog.attach()?;

    let nmi_prog: &mut PerfEvent = bpf.program_mut("spica_nmi").unwrap().try_into()?;
    nmi_prog.load()?;
    let cpus = online_cpus().map_err(|(_, e)| e)?;
    for cpu in &cpus {
        nmi_prog.attach(
            PerfEventConfig::Hardware(HardwareEvent::CpuCycles),
            PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            SamplePolicy::Frequency(1000),
            true,
        )?;
    }

    let sched_rb = RingBuf::try_from(bpf.take_map("EVENTS_SCHED").unwrap())?;
    let nmi_rb   = RingBuf::try_from(bpf.take_map("EVENTS_NMI").unwrap())?;
    let mut sched_fd = AsyncFd::new(sched_rb)?;
    let mut nmi_fd   = AsyncFd::new(nmi_rb)?;

    let mut registry: ProcessRegistry = HashMap::new();
    let mut last_sched_event          = Instant::now();
    let mut last_nmi_event            = Instant::now();
    let mut sched_silent_alerted: Option<Instant> = None;
    let mut nmi_silent_alerted:   Option<Instant> = None;

    // Seed registry with all processes already running at startup.
    // sched_last_seen is set to prevent spurious TAMPER alerts during the grace
    // window — long-running processes appear in NMI before their next sched event.
    // start_time_ns is 0 (unknown) and will be anchored on the first real eBPF event.
    let startup = Instant::now();
    for tgid in read_proc_tgids() {
        registry.insert(tgid, ProcessRecord {
            start_time_ns:       0,
            first_seen:          startup,
            sched_last_seen:     Some(startup),
            nmi_last_seen:       None,
            dkom_suspect_since:  None,
            ghost_suspect_since: None,
            alerts: AlertState { last_dkom: None, last_tamper: None, last_ghost: None },
        });
    }

    println!("I'm going to sing, so shine bright, SPiCa...");

    // ── Main loop ─────────────────────────────────────────────────────────────
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_RATE_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            guard = sched_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    process_event(&deobfuscate(raw), &mut registry, Channel::Sched);
                    last_sched_event = Instant::now();
                }
                guard.clear_ready();
            }
            guard = nmi_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    process_event(&deobfuscate(raw), &mut registry, Channel::Nmi);
                    last_nmi_event = Instant::now();
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                run_detection(&mut registry);
                // [SILENT]: one channel dark while the other is alive.
                let silence  = Duration::from_secs(SILENCE_THRESHOLD_SECS);
                let cooldown = Duration::from_secs(ALERT_COOLDOWN_SECS);
                if startup.elapsed() > silence {
                    if last_nmi_event.elapsed() > silence && last_sched_event.elapsed() < silence {
                        let should_alert = nmi_silent_alerted.map(|t| t.elapsed() > cooldown).unwrap_or(true);
                        if should_alert {
                            nmi_silent_alerted = Some(Instant::now());
                            println!("[SILENT]     NMI channel dark — perf_event DKOM or detachment suspected");
                        }
                    } else {
                        nmi_silent_alerted = None;
                    }
                    if last_sched_event.elapsed() > silence && last_nmi_event.elapsed() < silence {
                        let should_alert = sched_silent_alerted.map(|t| t.elapsed() > cooldown).unwrap_or(true);
                        if should_alert {
                            sched_silent_alerted = Some(Instant::now());
                            println!("[SILENT]     sched_switch channel dark — tracepoint detachment suspected");
                        }
                    } else {
                        sched_silent_alerted = None;
                    }
                }
            }
            _ = sigterm.recv() => { break; }
            _ = tokio::signal::ctrl_c() => { break; }
        }
    }

    println!("Catch me! I'll leap over Denebola");

    Ok(())
}
