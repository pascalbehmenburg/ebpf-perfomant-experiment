#![no_std]
#![no_main]

use core::str;

use aya_ebpf::{
    bindings::{bpf_perf_event_data, bpf_perf_event_value}, helpers::{bpf_get_current_comm, bpf_get_smp_processor_id, gen::{bpf_get_stackid, bpf_perf_prog_read_value, bpf_trace_vprintk}}, macros::perf_event, maps::PerfEventArray, programs::PerfEventContext, EbpfContext
};
use aya_log_ebpf::info;

static AGENT_NAME: &'static str = "performant";

struct PerfomanceEventReport<'a> {
    agent_name: &'static str,
    process_name: &'a str,
    cpu: u32,
    pid: u32,
}

#[perf_event]
pub fn performant(ctx: PerfEventContext) -> u32 {
    match try_performant(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_performant(ctx: PerfEventContext) -> Result<u32, u32> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let process_name = bpf_get_current_comm().map_err(|e| e as u32)?;
    let report = PerfomanceEventReport {
        agent_name: AGENT_NAME,
        process_name: unsafe { core::str::from_utf8_unchecked(&process_name) },
        cpu,
        pid: ctx.pid(),
    };
    info!(&ctx, "{{\"agent_name\": \"{}\", \"process_name\": \"{}\", \"cpu\": {}, \"pid\": {}}}", report.agent_name, report.process_name, report.cpu, report.pid);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
