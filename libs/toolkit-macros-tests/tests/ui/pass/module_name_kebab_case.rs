// Test that valid kebab-case module names are accepted

#[toolkit::module(
    name = "file-parser",  // Valid kebab-case
    capabilities = []
)]
#[derive(Default)]
pub struct FileParserModule;

#[async_trait::async_trait]
impl toolkit::Module for FileParserModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

#[toolkit::module(
    name = "simple-user-settings",  // Valid kebab-case with multiple hyphens
    capabilities = []
)]
#[derive(Default)]
pub struct SettingsModule;

#[async_trait::async_trait]
impl toolkit::Module for SettingsModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

#[toolkit::module(
    name = "api-gateway",  // Valid kebab-case
    capabilities = []
)]
#[derive(Default)]
pub struct ApiGatewayModule;

#[async_trait::async_trait]
impl toolkit::Module for ApiGatewayModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

#[toolkit::module(
    name = "module-v2",  // Valid kebab-case with digit
    capabilities = []
)]
#[derive(Default)]
pub struct ModuleV2;

#[async_trait::async_trait]
impl toolkit::Module for ModuleV2 {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

#[toolkit::module(
    name = "system",  // Valid single word (no hyphens needed)
    capabilities = []
)]
#[derive(Default)]
pub struct SystemModule;

#[async_trait::async_trait]
impl toolkit::Module for SystemModule {
    async fn init(&self, _ctx: &toolkit::ModuleCtx) -> anyhow::Result<()> {
        Ok(())
    }
}

fn main() {}
