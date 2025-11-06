pub mod simple;
pub mod verify;
pub mod testmod;

use anyhow::Result;
use crate::options::Options;

pub async fn run_scan(opt: Options) -> Result<()> {
    // For now use simple scanner implementation
    simple::run(opt).await
}

pub async fn run_verify(opt: Options) -> Result<()> {
    verify::run(opt).await
}

pub async fn run_test(opt: Options) -> Result<()> {
    testmod::run(opt).await
}
