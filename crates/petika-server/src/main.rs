use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "The Petika API server is not implemented. {}",
        petika_core::STATUS
    );
    ExitCode::FAILURE
}
