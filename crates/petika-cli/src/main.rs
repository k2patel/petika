use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => help(),
        [arg] if arg == "--help" || arg == "-h" => help(),
        [arg] if arg == "--version" || arg == "-V" => {
            println!("petika {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!("Unsupported command. {}", petika_core::STATUS);
            eprintln!("Run petika --help for the current interface.");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn help() {
    println!("Petika — an open-source, self-hosted password manager");
    println!("\nUsage: petika [--help | --version]");
    println!("\n{}", petika_core::STATUS);
}
