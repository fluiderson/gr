// Test that module names ending with hyphen are rejected

use toolkit::Module;

#[toolkit::module(
    name = "parser-",  // Should fail: ends with hyphen
    capabilities = []
)]
pub struct TestModule;

impl Module for TestModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

fn main() {}
