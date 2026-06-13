// swift-tools-version: 6.0
import PackageDescription

// SEPassCore holds the platform-independent OpenPGP + crypto logic for SE Pass.
// It is intentionally free of any Secure Enclave / UIKit dependency so the whole
// key-export and decryption pipeline can be unit-tested on macOS (and round-tripped
// against a real `gpg`). The iOS app injects a Secure Enclave-backed key provider;
// tests inject a software P-256 key.
let package = Package(
    name: "SEPassCore",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "SEPassCore", targets: ["SEPassCore"]),
    ],
    dependencies: [
        // Pure-Swift SSH (with native Secure Enclave signing) for the SSH git transport.
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.13.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.60.0"),
    ],
    targets: [
        .target(
            name: "SEPassCore",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "SEPassCoreTests",
            dependencies: [
                "SEPassCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
            ],
            resources: [.copy("Fixtures")]
        ),
    ]
)
