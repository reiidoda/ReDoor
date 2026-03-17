import Foundation

final class ZeroizableSecureBuffer {
    private var bytes: [UInt8]

    init(_ string: String) {
        self.bytes = Array(string.utf8)
    }

    deinit {
        wipe()
    }

    func update(with string: String) {
        wipe()
        bytes = Array(string.utf8)
    }

    func snapshotString() -> String? {
        String(bytes: bytes, encoding: .utf8)
    }

    func wipe() {
        guard !bytes.isEmpty else { return }
        for idx in bytes.indices {
            bytes[idx] = 0
        }
    }

    var byteCount: Int {
        bytes.count
    }

    #if DEBUG
    func debugAllBytesZero() -> Bool {
        bytes.allSatisfy { $0 == 0 }
    }
    #endif
}

public enum SecureStorage {
    // RAM-only volatile map. Nothing is persisted to device storage.
    private static var volatileStore: [String: ZeroizableSecureBuffer] = [:]
    private static let lock = NSLock()

    #if DEBUG
    private struct ZeroizationRecord {
        let byteCount: Int
        let allBytesZero: Bool
    }

    private static var zeroizationRecords: [String: ZeroizationRecord] = [:]
    #endif

    public static func save(key: String, data: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let existing = volatileStore[key] {
            existing.update(with: data)
            return
        }
        volatileStore[key] = ZeroizableSecureBuffer(data)
    }

    public static func load(key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return volatileStore[key]?.snapshotString()
    }

    private static func wipeAndRemove(key: String) {
        guard let existing = volatileStore[key] else { return }
        existing.wipe()
        #if DEBUG
        zeroizationRecords[key] = ZeroizationRecord(
            byteCount: existing.byteCount,
            allBytesZero: existing.debugAllBytesZero()
        )
        #endif
        volatileStore.removeValue(forKey: key)
    }

    public static func delete(key: String) {
        lock.lock()
        defer { lock.unlock() }
        wipeAndRemove(key: key)
    }

    public static func clearAll() {
        lock.lock()
        defer { lock.unlock() }
        let keys = Array(volatileStore.keys)
        for key in keys {
            wipeAndRemove(key: key)
        }
        volatileStore.removeAll(keepingCapacity: false)
    }

    #if DEBUG
    public static func debugLastZeroization(for key: String) -> (byteCount: Int, allBytesZero: Bool)? {
        lock.lock()
        defer { lock.unlock() }
        guard let record = zeroizationRecords[key] else {
            return nil
        }
        return (record.byteCount, record.allBytesZero)
    }

    public static func debugResetZeroizationRecords() {
        lock.lock()
        defer { lock.unlock() }
        zeroizationRecords.removeAll(keepingCapacity: false)
    }
    #endif
}

public enum SensitiveFieldStore {
    private static let hmacStorageKey = "redoor_hmac_key_volatile"

    @discardableResult
    public static func saveHMAC(_ value: String?) -> Bool {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if trimmed.isEmpty {
            SecureStorage.delete(key: hmacStorageKey)
            return true
        }
        do {
            try SecureStorage.save(key: hmacStorageKey, data: trimmed)
            return true
        } catch {
            return false
        }
    }

    public static func loadHMAC() -> String? {
        SecureStorage.load(key: hmacStorageKey)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func clearHMAC() {
        SecureStorage.delete(key: hmacStorageKey)
    }
}

public enum HMACKeyStore {
    #if DEBUG
    static var debugStorageKey: String { "redoor_hmac_key_volatile" }
    #endif

    public static func load() -> String? {
        SensitiveFieldStore.loadHMAC()
    }

    @discardableResult
    public static func save(_ value: String?) -> Bool {
        SensitiveFieldStore.saveHMAC(value)
    }

    public static func clearPersistent() {
        SensitiveFieldStore.clearHMAC()
    }
}
