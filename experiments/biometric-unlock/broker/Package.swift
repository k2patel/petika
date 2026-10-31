// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "PetikaDeviceBroker", platforms: [.macOS(.v13)],
    products: [.executable(name: "petika-broker-probe", targets: ["BrokerProbe"])],
    targets: [.target(name: "DeviceBroker"),
              .executableTarget(name: "BrokerProbe", dependencies: ["DeviceBroker"]),
              .testTarget(name: "DeviceBrokerTests", dependencies: ["DeviceBroker"])])
