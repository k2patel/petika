// swift-tools-version: 5.9
import PackageDescription

// A real package lets CodeQL autobuild discover the isolated Apple probe.
let package = Package(
    name: "PetikaBiometricProbe",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "petika-apple-probe", targets: ["AppleProbe"])],
    targets: [.executableTarget(name: "AppleProbe", path: ".",
        exclude: ["browser", "README.md", "test_browser.py"], sources: ["apple.swift"])]
)
