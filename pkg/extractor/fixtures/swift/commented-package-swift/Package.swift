// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.6.0"),
        // .package(url: "https://github.com/apple/swift-argument-parser", exact: "1.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "MyApp",
            dependencies: ["Alamofire"]
        ),
    ]
)
