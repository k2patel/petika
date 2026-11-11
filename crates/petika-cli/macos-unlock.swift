import CryptoKit
import Foundation
import LocalAuthentication
import Security

private enum UnlockError: Error {
    case invalid, unavailable
}

private struct Credential: Codable {
    let version: Int
    let deviceKey: Data
    let devicePublicKey: Data
    let ephemeralPublicKey: Data
    let ciphertext: Data

    var binding: Data {
        Data("petika.cli.local-vault.touch-id.v1".utf8) + devicePublicKey + ephemeralPublicKey
    }
}

private func readInput(limit: Int) throws -> Data {
    var input = Data()
    while input.count <= limit {
        guard let chunk = try FileHandle.standardInput.read(upToCount: limit + 1 - input.count),
              !chunk.isEmpty else { return input }
        input.append(chunk)
    }
    throw UnlockError.invalid
}

private func biometricContext(reason: String) throws -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    guard SecureEnclave.isAvailable,
          context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
          context.biometryType == .touchID else {
        context.invalidate()
        throw UnlockError.unavailable
    }
    return context
}

private func wrappingKey(_ shared: SharedSecret, binding: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: binding,
        sharedInfo: Data("petika.cli.local-vault.wrap.v1".utf8),
        outputByteCount: 32
    )
}

private func unlock(_ credential: Credential, reason: String) throws -> Data {
    guard credential.version == 1,
          (1..<8192).contains(credential.deviceKey.count),
          credential.devicePublicKey.count == 64,
          credential.ephemeralPublicKey.count == 64,
          credential.ciphertext.count == 60 else { throw UnlockError.invalid }
    let context = try biometricContext(reason: reason)
    defer { context.invalidate() }
    let device = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: credential.deviceKey, authenticationContext: context
    )
    guard device.publicKey.rawRepresentation == credential.devicePublicKey else {
        throw UnlockError.invalid
    }
    let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: credential.ephemeralPublicKey)
    let shared = try device.sharedSecretFromKeyAgreement(with: ephemeral)
    return try AES.GCM.open(
        AES.GCM.SealedBox(combined: credential.ciphertext),
        using: wrappingKey(shared, binding: credential.binding),
        authenticating: credential.binding
    )
}

private func enroll(_ key: Data) throws -> Credential {
    guard key.count == 32 else { throw UnlockError.invalid }
    let context = try biometricContext(reason: "Enable Touch ID for your Petika vault")
    defer { context.invalidate() }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], nil
    ) else { throw UnlockError.unavailable }
    let device = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let devicePublicKey = device.publicKey.rawRepresentation
    let ephemeralPublicKey = ephemeral.publicKey.rawRepresentation
    let framing = Credential(
        version: 1, deviceKey: device.dataRepresentation, devicePublicKey: devicePublicKey,
        ephemeralPublicKey: ephemeralPublicKey, ciphertext: Data()
    )
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: device.publicKey)
    let sealed = try AES.GCM.seal(
        key, using: wrappingKey(shared, binding: framing.binding),
        authenticating: framing.binding
    )
    guard let ciphertext = sealed.combined else { throw UnlockError.invalid }
    let credential = Credential(
        version: framing.version, deviceKey: framing.deviceKey, devicePublicKey: devicePublicKey,
        ephemeralPublicKey: ephemeralPublicKey, ciphertext: ciphertext
    )
    var check = try unlock(credential, reason: "Enable Touch ID for your Petika vault")
    defer { check.resetBytes(in: 0..<check.count) }
    guard check == key else { throw UnlockError.invalid }
    return credential
}

do {
    guard CommandLine.arguments.count == 2 else { throw UnlockError.invalid }
    switch CommandLine.arguments[1] {
    case "status":
        let context = try biometricContext(reason: "Check Petika Touch ID availability")
        context.invalidate()
        try FileHandle.standardOutput.write(contentsOf: Data("available\n".utf8))
    case "enroll":
        var key = try readInput(limit: 32)
        defer { key.resetBytes(in: 0..<key.count) }
        try FileHandle.standardOutput.write(contentsOf: JSONEncoder().encode(enroll(key)))
    case "unlock":
        let credential = try JSONDecoder().decode(Credential.self, from: readInput(limit: 16 * 1024))
        var key = try unlock(credential, reason: "Unlock your Petika vault")
        defer { key.resetBytes(in: 0..<key.count) }
        try FileHandle.standardOutput.write(contentsOf: key)
    default:
        throw UnlockError.invalid
    }
} catch {
    exit(EXIT_FAILURE)
}
