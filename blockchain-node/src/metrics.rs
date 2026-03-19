use once_cell::sync::OnceCell;
use prometheus::{Encoder, IntCounter, Opts, Registry, TextEncoder};

static REG: OnceCell<Registry> = OnceCell::new();
static BLOCKS_COUNTER: OnceCell<IntCounter> = OnceCell::new();
static SIGNED_BLOCKS_COUNTER: OnceCell<IntCounter> = OnceCell::new();

fn registry() -> &'static Registry {
    REG.get_or_init(|| Registry::new())
}

pub fn init_metrics() {
    let reg = registry();
    let blocks = IntCounter::with_opts(Opts::new("blocks_appended", "Number of blocks appended"))
        .expect("create counter");
    let signed = IntCounter::with_opts(Opts::new(
        "signed_blocks_appended",
        "Number of signed blocks appended",
    ))
    .expect("create counter");
    let _ = reg.register(Box::new(blocks.clone()));
    let _ = reg.register(Box::new(signed.clone()));
    let _ = BLOCKS_COUNTER.set(blocks);
    let _ = SIGNED_BLOCKS_COUNTER.set(signed);
}

pub fn inc_blocks_appended() {
    if let Some(c) = BLOCKS_COUNTER.get() {
        c.inc();
    }
}

pub fn inc_signed_blocks_appended() {
    if let Some(c) = SIGNED_BLOCKS_COUNTER.get() {
        c.inc();
    }
}

pub fn gather_metrics() -> String {
    let reg = registry();
    let encoder = TextEncoder::new();
    let metric_families = reg.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
