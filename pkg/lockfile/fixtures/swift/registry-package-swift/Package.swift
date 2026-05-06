// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(id: "apple.swift-argument-parser", from: "1.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "MyApp",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
    ]
)
