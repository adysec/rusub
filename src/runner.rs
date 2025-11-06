use crate::options::Options;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Notify;
use crate::scanner;

pub struct Runner {
    pub options: Options,
    pub shutdown: Arc<Notify>,
}

impl Runner {
    pub fn new(opt: Options) -> Result<Self> {
        // placeholder: real init (pcap, statusdb, channels) will be added
        Ok(Runner { options: opt, shutdown: Arc::new(Notify::new()) })
    }

    pub async fn run_enumeration(&self) -> Result<()> {
        // placeholder: start send/recv loops
        println!("runner: start_enumeration (placeholder)");
        // use scanner simple implementation
        scanner::run_scan(self.options.clone()).await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.shutdown.notify_waiters();
    }
}
