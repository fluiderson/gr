// Test that module names with uppercase letters are rejected

use toolkit::Module;

#[toolkit::module(
    name = "FileParser",  // Should fail: contains uppercase letters
    capabilities = []
)]
pub struct TestModule;

impl Module for TestModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

fn main() {}
