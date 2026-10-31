// Synthetic-only experiment. This is not a Petika vault or network API.
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

public enum BrokerFailure: Error { case denied, invalid, storage, busy, replay }
public enum SecretAction: String { case show, copy }

struct Credential: Codable {
    let version: Int
    let device: UUID
    let publicKey: Data
    let opaqueKey: Data
    let ephemeral: Data
    let wrappedSeed: Data
    let entry: Data
    var binding: Data {
        Data("petika.synthetic.device-broker.v1:".utf8) + Data(device.uuidString.utf8)
            + publicKey + ephemeral
    }
    func validate() throws {
        guard version == 1, publicKey.count == 64, ephemeral.count == 64,
              !opaqueKey.isEmpty, opaqueKey.count < 8192,
              wrappedSeed.count == 60, entry.count == 60 else { throw BrokerFailure.invalid }
        _ = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        _ = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeral)
    }
    static func load(_ url: URL) throws -> Credential {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw BrokerFailure.storage }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_uid == getuid(), metadata.st_size <= 16384 else {
            throw BrokerFailure.storage
        }
        var data = Data()
        while data.count <= 16384 {
            guard let part = try handle.read(upToCount: 16385 - data.count), !part.isEmpty else { break }
            data.append(part)
        }
        guard data.count <= 16384,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["version", "device", "publicKey", "opaqueKey", "ephemeral", "wrappedSeed", "entry"]) else {
            throw BrokerFailure.invalid
        }
        let record = try JSONDecoder().decode(Credential.self, from: data)
        try record.validate()
        return record
    }
    func persist(_ url: URL) throws {
        try validate()
        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        let temp = parent.appendingPathComponent(".broker-" + UUID().uuidString)
        let fd = Darwin.open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw BrokerFailure.storage }
        defer { Darwin.close(fd); Darwin.unlink(temp.path) }
        let bytes = try JSONEncoder().encode(self)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                guard written > 0 else { throw BrokerFailure.storage }
                offset += written
            }
        }
        guard fsync(fd) == 0, Darwin.link(temp.path, url.path) == 0 else { throw BrokerFailure.storage }
        let directory = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY)
        guard directory >= 0 else { throw BrokerFailure.storage }
        defer { Darwin.close(directory) }
        guard fsync(directory) == 0 else { throw BrokerFailure.storage }
    }
}

func wrapperKey(_ secret: SharedSecret, _ binding: Data) -> SymmetricKey {
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: binding,
        sharedInfo: Data("petika.synthetic.device-broker.wrap.v1".utf8), outputByteCount: 32)
}
func entryKey(_ seed: Data, _ binding: Data) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: seed), salt: binding,
        info: Data("petika.synthetic.device-broker.entry.v1".utf8), outputByteCount: 32)
}
protocol ProtectedSeed {
    func open(_ record: Credential, action: SecretAction) throws -> Data
}
struct EnclaveSeed: ProtectedSeed {
    func open(_ record: Credential, action: SecretAction) throws -> Data {
        let context = LAContext()
        context.localizedReason = "Petika generated-data test: approve \(action.rawValue) once"
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        defer { context.invalidate() }
        guard SecureEnclave.isAvailable,
              context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            throw BrokerFailure.denied
        }
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: record.opaqueKey, authenticationContext: context)
        guard privateKey.publicKey.rawRepresentation == record.publicKey else { throw BrokerFailure.invalid }
        let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: record.ephemeral)
        let key = wrapperKey(try privateKey.sharedSecretFromKeyAgreement(with: ephemeral), record.binding)
        return try AES.GCM.open(AES.GCM.SealedBox(combined: record.wrappedSeed),
                                using: key, authenticating: record.binding)
    }
}

// Internal action requests are never transferable unlock permits. Every successful
// request still enters ProtectedSeed.open; no key or biometric context is cached.
struct ActionRequest {
    let nonce: UUID
    let action: SecretAction
    let device: UUID
    let digest: Data
    let created: TimeInterval
}
public final class SyntheticBroker {
    private let record: Credential
    private let protected: ProtectedSeed
    private let lock = NSLock()
    private var consumed = Set<UUID>()
    private let clock: () -> TimeInterval
    init(record: Credential, protected: ProtectedSeed,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) throws {
        try record.validate()
        self.record = record; self.protected = protected; self.clock = clock
    }
    public convenience init(url: URL) throws {
        try self.init(record: Credential.load(url), protected: EnclaveSeed())
    }
    func request(_ action: SecretAction) -> ActionRequest {
        ActionRequest(nonce: UUID(), action: action, device: record.device,
                      digest: Data(SHA256.hash(data: record.entry)), created: clock())
    }
    func execute(_ request: ActionRequest, expected: SecretAction) throws -> Data {
        guard lock.try() else { throw BrokerFailure.busy }
        defer { lock.unlock() }
        guard request.action == expected, request.device == record.device,
              request.digest == Data(SHA256.hash(data: record.entry)),
              clock() >= request.created, clock() - request.created <= 30 else {
            throw BrokerFailure.invalid
        }
        guard consumed.count < 1024, consumed.insert(request.nonce).inserted else { throw BrokerFailure.replay }
        // Failed/cancelled requests are consumed too; retry creates a new request.
        var seed = try protected.open(record, action: request.action)
        defer { seed.resetBytes(in: 0..<seed.count) }
        guard seed.count == 32 else { throw BrokerFailure.invalid }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: record.entry),
            using: entryKey(seed, record.binding), authenticating: record.binding)
    }
    // Output is a digest of generated test data, never a vault/key or clipboard write.
    // The distinct copy action models a bounded sink; OS clipboard integration is later work.
    public func perform(_ action: SecretAction) throws -> String {
        var output = try execute(request(action), expected: action)
        defer { output.resetBytes(in: 0..<output.count) }
        return SHA256.hash(data: output).map { String(format: "%02x", $0) }.joined()
    }
    public static func create(at url: URL) throws {
        let capability = LAContext()
        defer { capability.invalidate() }
        guard SecureEnclave.isAvailable,
              capability.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            throw BrokerFailure.denied
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error) else { throw BrokerFailure.denied }
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let device = UUID()
        let publicKey = enclave.publicKey.rawRepresentation
        let enc = ephemeral.publicKey.rawRepresentation
        let binding = Data("petika.synthetic.device-broker.v1:".utf8) + Data(device.uuidString.utf8) + publicKey + enc
        let wrapping = wrapperKey(try ephemeral.sharedSecretFromKeyAgreement(with: enclave.publicKey), binding)
        var seed = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        var payload = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        defer { seed.resetBytes(in: 0..<seed.count); payload.resetBytes(in: 0..<payload.count) }
        let record = Credential(version: 1, device: device, publicKey: publicKey,
            opaqueKey: enclave.dataRepresentation, ephemeral: enc,
            wrappedSeed: try AES.GCM.seal(seed, using: wrapping, authenticating: binding).combined!,
            entry: try AES.GCM.seal(payload, using: entryKey(seed, binding), authenticating: binding).combined!)
        try record.persist(url)
    }
}
