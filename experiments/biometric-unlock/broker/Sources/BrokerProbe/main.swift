import DeviceBroker
import Foundation
// Only generated test state is accepted; no Petika account/vault/password input.
do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard args.count == 2 else { throw BrokerFailure.invalid }
    let url = URL(fileURLWithPath: args[1])
    switch args[0] {
    case "create":
        try SyntheticBroker.create(at: url)
        print("synthetic_credential_created=true secrets_printed=false")
    case "show", "copy":
        let broker = try SyntheticBroker(url: url)
        _ = try broker.perform(args[0] == "show" ? .show : .copy)
        print("synthetic_action=\(args[0]) completed=true keys_cached=false clipboard_written=false")
    case "roundtrip":
        let first = try SyntheticBroker(url: url).perform(.show)
        let second = try SyntheticBroker(url: url).perform(.copy)
        guard first == second else { throw BrokerFailure.invalid }
        print("reopened=true show_and_copy_match=true protected_operations=2 clipboard_written=false")
    default: throw BrokerFailure.invalid
    }
} catch {
    print("synthetic_operation_denied=true fallback=none")
    exit(1)
}
