// Isolated synthetic-data probe. No production keys, files, or accounts accepted.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum ProbeError: Error { case unavailable, accessControl, mismatch, rejectionFailed }

let context = Data("petika.synthetic.local-wrapper.v1".utf8)

func wrappingKey(_ secret: SharedSecret, _ binding: Data) -> SymmetricKey {
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: binding,
                                  sharedInfo: context, outputByteCount: 32)
}

func expectRejected(_ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw ProbeError.rejectionFailed
}

func softwareTests() throws {
    let recipient = P256.KeyAgreement.PrivateKey()
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let binding = recipient.publicKey.rawRepresentation + ephemeral.publicKey.rawRepresentation
    let sealKey = wrappingKey(try ephemeral.sharedSecretFromKeyAgreement(with: recipient.publicKey), binding)
    let openKey = wrappingKey(try recipient.sharedSecretFromKeyAgreement(with: ephemeral.publicKey), binding)
    let synthetic = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    let box = try AES.GCM.seal(synthetic, using: sealKey, authenticating: binding)
    guard try AES.GCM.open(box, using: openKey, authenticating: binding) == synthetic else {
        throw ProbeError.mismatch
    }
    try expectRejected { _ = try AES.GCM.open(box, using: openKey, authenticating: context) }
    try expectRejected { _ = try AES.GCM.open(box, using: SymmetricKey(size: .bits256), authenticating: binding) }
    var modified = box.combined!
    modified[modified.count - 1] ^= 1
    try expectRejected {
        _ = try AES.GCM.open(AES.GCM.SealedBox(combined: modified), using: openKey, authenticating: binding)
    }
    print("software_wrapper_roundtrip=true wrong_key_rejected=true context_tamper_rejected=true ciphertext_tamper_rejected=true hardware_test=false")
}

func hardwareRoundtrip() throws {
    let availability = LAContext()
    guard SecureEnclave.isAvailable,
          availability.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
        throw ProbeError.unavailable
    }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error) else {
        throw ProbeError.accessControl
    }
    let original = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    // This opaque representation is hardware-wrapped; it is never exported to disk/logs.
    let opaqueRepresentation = original.dataRepresentation
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let binding = original.publicKey.rawRepresentation + ephemeral.publicKey.rawRepresentation
    let key = wrappingKey(try ephemeral.sharedSecretFromKeyAgreement(with: original.publicKey), binding)
    let synthetic = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    let box = try AES.GCM.seal(synthetic, using: key, authenticating: binding)
    let authentication = LAContext()
    authentication.localizedReason = "Open generated Petika test data"
    authentication.localizedFallbackTitle = ""
    authentication.touchIDAuthenticationAllowableReuseDuration = 0
    defer { authentication.invalidate() }
    let restored = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: opaqueRepresentation, authenticationContext: authentication)
    // Access control gates the ECDH operation itself; no evaluatePolicy boolean bypass.
    let restoredKey = wrappingKey(try restored.sharedSecretFromKeyAgreement(with: ephemeral.publicKey), binding)
    guard try AES.GCM.open(box, using: restoredKey, authenticating: binding) == synthetic else {
        throw ProbeError.mismatch
    }
    print("secure_enclave_roundtrip=true biometric_policy=current_set fallback=none persisted=false")
}

do {
    switch Array(CommandLine.arguments.dropFirst()) {
    case []:
        let authentication = LAContext()
        var error: NSError?
        let available = authentication.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        print("os=\(ProcessInfo.processInfo.operatingSystemVersionString)")
        print("secure_enclave=\(SecureEnclave.isAvailable) biometrics=\(available) biometry_type=\(authentication.biometryType.rawValue) error_code=\(error?.code ?? 0)")
        print("hardware_roundtrip=not_run persisted=false")
    case ["--software-test"]: try softwareTests()
    case ["--hardware-roundtrip"]: try hardwareRoundtrip()
    default:
        print("usage: apple-probe [--software-test | --hardware-roundtrip]")
        exit(2)
    }
} catch {
    // Do not print localized errors, underlying objects, or cryptographic material.
    print("probe_failed=true error_code=\((error as NSError).code) fallback=none")
    exit(1)
}
