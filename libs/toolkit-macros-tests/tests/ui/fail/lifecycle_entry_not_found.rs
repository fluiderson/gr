use toolkit_macros::module;
use tokio_util::sync::CancellationToken;
use anyhow::Result;

#[module(name="x", capabilities=[stateful], lifecycle(entry="serve", await_ready))]
pub struct X;

impl X {
    // Wrong signature: missing ReadySignal parameter → the generated call won't match.
    async fn serve(&self, _cancel: CancellationToken) -> Result<()> { Ok(()) }
}

#[async_trait::async_trait]
impl toolkit::Module for X {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> { Ok(()) }
}

fn main() {}
