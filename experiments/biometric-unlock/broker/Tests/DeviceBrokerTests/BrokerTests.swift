import CryptoKit
import Foundation
import XCTest
@testable import DeviceBroker

final class SoftwareSeed: ProtectedSeed {
    let privateKey = P256.KeyAgreement.PrivateKey()
    var actions: [SecretAction] = []
    var deny = false
    func open(_ record: Credential, action: SecretAction) throws -> Data {
        actions.append(action)
        if deny { throw BrokerFailure.denied }
        let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: record.ephemeral)
        return try AES.GCM.open(AES.GCM.SealedBox(combined: record.wrappedSeed),
            using: wrapperKey(try privateKey.sharedSecretFromKeyAgreement(with: ephemeral), record.binding),
            authenticating: record.binding)
    }
    func fixture() throws -> Credential {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let device = UUID()
        let publicKey = privateKey.publicKey.rawRepresentation
        let enc = ephemeral.publicKey.rawRepresentation
        let binding = Data("petika.synthetic.device-broker.v1:".utf8) + Data(device.uuidString.utf8) + publicKey + enc
        let seed = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let wrapped = try AES.GCM.seal(seed,
            using: wrapperKey(try ephemeral.sharedSecretFromKeyAgreement(with: privateKey.publicKey), binding),
            authenticating: binding).combined!
        return Credential(version: 1, device: device, publicKey: publicKey, opaqueKey: Data([1]), ephemeral: enc,
            wrappedSeed: wrapped,
            entry: try AES.GCM.seal(Data(repeating: 7, count: 32), using: entryKey(seed, binding), authenticating: binding).combined!)
    }
}
final class BrokerTests: XCTestCase {
    func testEveryActionCallsProtectionAgainAndReplayIsDenied() throws {
        let protection = SoftwareSeed()
        let broker = try SyntheticBroker(record: protection.fixture(), protected: protection)
        let first = try broker.perform(.show)
        XCTAssertEqual(first, try broker.perform(.copy))
        XCTAssertEqual(first, try broker.perform(.show))
        XCTAssertEqual(protection.actions, [.show, .copy, .show])
        let request = broker.request(.copy)
        _ = try broker.execute(request, expected: .copy)
        XCTAssertThrowsError(try broker.execute(request, expected: .copy))
        XCTAssertEqual(protection.actions.count, 4)
    }
    func testDenialDoesNotReusePreviousApprovalAndConsumesFailedRequest() throws {
        let protection = SoftwareSeed()
        let broker = try SyntheticBroker(record: protection.fixture(), protected: protection)
        _ = try broker.perform(.show)
        protection.deny = true
        let request = broker.request(.copy)
        XCTAssertThrowsError(try broker.execute(request, expected: .copy))
        protection.deny = false
        XCTAssertThrowsError(try broker.execute(request, expected: .copy))
        _ = try broker.perform(.copy)
        XCTAssertEqual(protection.actions, [.show, .copy, .copy])
    }
    func testWrongActionDeviceDigestAndExpiredRequestsFailBeforeProtection() throws {
        let protection = SoftwareSeed()
        var now: TimeInterval = 100
        let record = try protection.fixture()
        let broker = try SyntheticBroker(record: record, protected: protection, clock: { now })
        let original = broker.request(.show)
        XCTAssertThrowsError(try broker.execute(original, expected: .copy))
        let wrongDevice = ActionRequest(nonce: UUID(), action: .show, device: UUID(), digest: original.digest, created: 100)
        XCTAssertThrowsError(try broker.execute(wrongDevice, expected: .show))
        let wrongDigest = ActionRequest(nonce: UUID(), action: .show, device: record.device, digest: Data(), created: 100)
        XCTAssertThrowsError(try broker.execute(wrongDigest, expected: .show))
        now = 131
        XCTAssertThrowsError(try broker.execute(original, expected: .show))
        now = 99
        XCTAssertThrowsError(try broker.execute(original, expected: .show))
        XCTAssertTrue(protection.actions.isEmpty)
    }
    func testPersistReopenNoClobberStrictFieldsAndPrivatePermissions() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("credential.json")
        let protection = SoftwareSeed()
        let original = try protection.fixture()
        try original.persist(path)
        XCTAssertThrowsError(try original.persist(path))
        let loaded = try Credential.load(path)
        XCTAssertEqual(loaded.device, original.device)
        XCTAssertEqual(try SyntheticBroker(record: loaded, protected: protection).perform(.show),
                       try SyntheticBroker(record: original, protected: protection).perform(.copy))
        let alias = dir.appendingPathComponent("alias.json")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: path)
        XCTAssertThrowsError(try Credential.load(alias))
        let oversized = dir.appendingPathComponent("oversized.json")
        _ = FileManager.default.createFile(atPath: oversized.path, contents: Data(repeating: 0, count: 16385), attributes: [.posixPermissions: 0o600])
        XCTAssertThrowsError(try Credential.load(oversized))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        XCTAssertThrowsError(try Credential.load(path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        var object = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        object["unrecognized"] = true
        try JSONSerialization.data(withJSONObject: object).write(to: path)
        XCTAssertThrowsError(try Credential.load(path))
    }
    func testCiphertextAndDeviceBindingTamperingCannotDecrypt() throws {
        let protection = SoftwareSeed()
        let record = try protection.fixture()
        var entry = record.entry
        entry[entry.count-1] ^= 1
        let changed = Credential(version: 1, device: record.device, publicKey: record.publicKey,
            opaqueKey: record.opaqueKey, ephemeral: record.ephemeral, wrappedSeed: record.wrappedSeed, entry: entry)
        XCTAssertThrowsError(try SyntheticBroker(record: changed, protected: protection).perform(.show))
        let different = Credential(version: 1, device: UUID(), publicKey: record.publicKey,
            opaqueKey: record.opaqueKey, ephemeral: record.ephemeral, wrappedSeed: record.wrappedSeed, entry: record.entry)
        XCTAssertThrowsError(try SyntheticBroker(record: different, protected: protection).perform(.show))
    }
}
