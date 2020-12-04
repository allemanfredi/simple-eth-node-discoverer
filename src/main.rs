use cli::Cli;
use peers::peers_handler::PeersHandler;
use settings::Settings;
use utils::app_error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let args = Cli::parse_params()?;
    let mut handler = PeersHandler::new(args.tcp_port);

    let settings = Settings::load()?;
    handler.spawn_discover(settings.default_peers).await?;

    handler.listen_for_peers().await?;

    Ok(())
}
