// Minimal stateful module with lifecycle (no ready)
use toolkit_macros::module;
use tokio_util::sync::CancellationToken;
use anyhow::Result;

#[derive(Default)]
#[module(name = "demo", capabilities = [stateful], lifecycle(entry = "serve", stop_timeout = "1s"))]
pub struct Demo;

impl Demo {
    async fn serve(&self, _cancel: CancellationToken) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl toolkit::Module for Demo {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

fn main() {}
