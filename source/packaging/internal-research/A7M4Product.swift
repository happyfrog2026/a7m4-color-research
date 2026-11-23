import AppKit
import AVFoundation
import CryptoKit
import CoreFoundation
import Darwin
import SwiftUI
import UniformTypeIdentifiers

enum ProductIdentity {
    static let knowledgeMapURL = URL(string: "https://github.com/happyfrog2026/a7m4-color-research")!
    static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.5.1-alpha.62" }
    static var iteration: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "62" }
    static var title: String { "A7 IV 工具箱 v\(version)" }
    // This test switch only removes capabilities. It never grants device I/O.
    static var offlineQA: Bool { ProcessInfo.processInfo.environment["A7M4_OFFLINE_QA"] == "1" }
    static var qaScenario: String {
        let value = ProcessInfo.processInfo.environment["A7M4_QA_SCENARIO"] ?? "start"
        return ["sequence-install", "sequence-restore", "sequence-failure", "low-space", "start", "backup-data", "backup-import", "restore-target", "cold-start", "install-cold-start", "install-cold-start-preflight", "st-protection", "st-protection-page", "final-acceptance", "final-acceptance-page", "filters", "sound", "restore-wait", "restore-run", "overdue", "complete", "identity-error", "about", "other"].contains(value) ? value : "start"
    }
    static var qaRoot: URL { FileManager.default.temporaryDirectory.appendingPathComponent("a7m4-alpha62-offline-qa", isDirectory: true).appendingPathComponent(qaScenario, isDirectory: true) }
}

// Presentation only: no cancellation, driver admission, retry or STOP decisions.
struct OperationEstimate {
    let profile: String
    let restoring: Bool
    let resumed: Bool
    let totalMinutes: Int
    let stageMinutes: Int
    static func roundedMinutes(measuredSeconds: Double) -> Int { measuredSeconds.isFinite ? 2 * Int(ceil(max(0, measuredSeconds) / 60)) : 0 }
    // Prior real runs used 73 files / 68 strings. These are conservative budgets,
    // not alpha.60 hardware measurements. Restore includes an incident continuation.
    var source: String { restoring ? "legacy73 incident path 1044.008s; 2*ceil(seconds/60); alpha60 hardware unmeasured" : profile == "backup" ? "legacy73 backup 37.3s; 2*ceil(seconds/60); alpha60 hardware unmeasured" : "legacy73 selected install 430.63399058s; 2*ceil(seconds/60); alpha60 hardware unmeasured" }
    static func select(_ args: [String], profile: String) -> OperationEstimate? {
        let operation = args.count > 1 && args[0] == "driver" ? args[1] : ""
        let restore = ["backup-target-restore", "backup-target-verify", "feature-c-restore"].contains(operation)
        guard restore || ["backup", "selected-install", "features"].contains(operation) else { return nil }
        let total = roundedMinutes(measuredSeconds: restore ? 1044.008 : operation == "backup" ? 37.3 : 430.63399058)
        return OperationEstimate(profile: restore ? "all-current" : operation == "selected-install" ? "selected" : operation == "backup" ? "backup" : profile,
            restoring: restore, resumed: restore && args.contains("--previous-job"), totalMinutes: total, stageMinutes: total)
    }
}

struct OperationProgress {
    var estimate: OperationEstimate?
    var fraction = 0.0
    var activeSeconds = 0.0
    var userWaitSeconds = 0.0
    var priorActiveSeconds = 0.0
    var priorWaitSeconds = 0.0
    var paused = false
    var phase = "IDLE"
    var base = 0.0
    var last = 0.0
    var complete = false
    var consumerSafetyStage = ""
    mutating func begin(_ value: OperationEstimate?, now: Double, wait: Bool, saved: Double = 0,
                        priorActive: Double = 0, priorWait: Double = 0) {
        self = OperationProgress(); estimate = value; last = now; paused = wait
        priorActiveSeconds = max(0, priorActive); priorWaitSeconds = max(0, priorWait)
        if value?.resumed == true { base = min(0.95, max(0, saved.isFinite ? saved : 0)) }
        fraction = base; phase = wait ? "WAITING_AUTHORIZATION" : value?.resumed == true ? "RESOURCE_FINISH" : "MACHINE_EXECUTION"
    }
    mutating func tick(now: Double, authorization: String? = nil) {
        guard !complete else { last = now; return }
        let delta = max(0, now-last); last = now
        if paused { userWaitSeconds += delta } else { activeSeconds += delta }
        if authorization == "RUNNING" { paused = false; phase = estimate?.resumed == true ? "RESOURCE_FINISH" : "MACHINE_EXECUTION" }
        guard !paused, let estimate, !complete else { return }
        fraction = min(0.95, max(fraction, (priorActiveSeconds + activeSeconds) / Double(estimate.totalMinutes*60)))
    }
    mutating func finish(accepted: Bool, verifiedComplete: Bool, checkpoint: Bool, now: Double) {
        tick(now: now)
        complete = accepted && verifiedComplete && !checkpoint
        if complete { fraction = 1; paused = false; phase = "VERIFIED_COMPLETE" }
        else if checkpoint { fraction = min(0.95,fraction); paused = true; phase = "WAITING_RESTART" }
        else { paused = false; phase = "STOPPED_WITHOUT_COMPLETION" }
    }
    @discardableResult mutating func finishInstallationCheck(verifiedWrite: Bool, userCompleted: Bool, now: Double) -> Bool {
        guard estimate?.profile == "selected", estimate?.restoring == false, paused,
              ["WAITING_RESTART", "WAITING_FUNCTION_CHECK"].contains(phase), verifiedWrite, userCompleted else { return false }
        finish(accepted: true, verifiedComplete: true, checkpoint: false, now: now)
        return true
    }
    var overdue: Bool { !paused && !complete && estimate.map { priorActiveSeconds + activeSeconds > Double($0.totalMinutes*60) } == true }
    var waitingMessage: String? {
        guard paused else { return nil }
        switch phase {
        case "WAITING_FUNCTION_CHECK":
            return estimate?.restoring == true ? "等待你确认恢复后的启动和拍摄正常；计时暂停。" : "等待你确认安装后的所选功能正常；计时暂停。"
        case "WAITING_RESTART":
            if estimate?.restoring == true && consumerSafetyStage == "ST_SAVED_PATCHES_RETAINED" {
                return "已保存 ST，程序补丁仍保留；请冷启动并回到 MSC 继续。人工等待单独计时，恢复尚未完成。"
            }
            return estimate?.restoring == true ? "等待你按恢复节点冷启动并回到 MSC；估算暂停，恢复尚未完成。" : "等待你按提示冷启动并检查所选功能；估算暂停，安装后的功能验收尚未完成。"
        case "WAITING_AUTHORIZATION":
            return "等待管理员授权；握手完成前不要关闭 Terminal。密码输入和人工等待不计机器执行时间。"
        default: return nil
        }
    }
    var metadata: [String: Any] {
        ["schema": "a7m4-presentation-timing/1", "phase": phase, "estimated_minutes": estimate?.totalMinutes as Any? ?? NSNull(),
         "stage_estimated_minutes": estimate?.stageMinutes as Any? ?? NSNull(), "machine_seconds": activeSeconds + priorActiveSeconds,
         "prior_machine_seconds": priorActiveSeconds, "user_wait_seconds": userWaitSeconds + priorWaitSeconds,
         "resumed": estimate?.resumed ?? false, "display_fraction": fraction, "verified_complete": complete,
         "consumer_safety_stage": consumerSafetyStage,
         "estimate_source": estimate?.source ?? "none"]
    }
}

// Local metadata-only diagnostics. No capture payloads or private job trees are exported.
enum ColdStartInstructions {
    static let stProtectionText = "已保存 ST，程序补丁仍保留；请按冷启动步骤重启、回到 MSC 后继续。重启后的机内模型核验通过，才会开始恢复程序。"
    static func consumerStage(_ value: [String: Any]?) -> String {
        let stage = (value?["consumer_safety"] as? [String: Any])?["stage"] as? String ?? ""
        return ["ST_SAVED_PATCHES_RETAINED", "LIVE_ST_VERIFIED"].contains(stage) ? stage : ""
    }
    static let text = "断开 USB-C → 拨 OFF 关机 → 等约 15 秒；垃圾桶图标旁的红灯若仍亮，继续等到熄灭 → 取出电池 → 等 30 秒 → 装回电池 → 开机 → 重新连接 USB 并进入海量存储 MSC。"
    static let finalText = "断开 USB-C → 拨 OFF 关机 → 等约 15 秒；垃圾桶图标旁的红灯若仍亮，继续等到熄灭 → 取出电池 → 等 30 秒 → 装回电池 → 开机 → 检查名称图标、快门声音、实际拍摄与照片回放。最终功能验收无需立即重新连接 USB 或进入 MSC。"
    static func finalAcceptance(_ value: [String: Any]?) -> Bool {
        guard let value, value["status"] as? String == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" else { return false }
        return DriverJobPolicy.verifiedBackupTargetCheckpoint(value)
    }
    static func canSubmitFinal(phase: String, safeReceipt: Bool, coldStart: Bool, observations: [Bool]) -> Bool {
        phase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" && safeReceipt && coldStart
            && observations.count == 4 && observations.allSatisfy { $0 }
    }
    static func required(_ value: [String: Any]?) -> Bool {
        guard let value, DriverJobPolicy.strictTrue(value["camera_io"]), DriverJobPolicy.strictFalse(value["simulation"]),
              ["normal_return_verified", "service_exit_confirmed", "stop_safe"].allSatisfy({ DriverJobPolicy.strictTrue(value[$0]) }) else { return false }
        if value["feature"] as? String == "selected-feature-install",
           value["status"] as? String == "STOPPED_PREFLIGHT_NORMAL_RETURN",
           DriverJobPolicy.strictFalse(value["persistent_write_phase_attempted"]),
           let proof = value["original_loaded_C_proof"] as? [String: Any],
           DriverJobPolicy.strictFalse(proof["C_loaded_verified"]), proof["native_status"] as? Int == -84,
           ["cleanup_safe", "no_memory_write", "no_COW"].allSatisfy({ DriverJobPolicy.strictTrue(proof[$0]) }),
           proof["boot_id"] as? String == value["boot_id"] as? String,
           proof["process_id"] as? Int == value["native_process_id"] as? Int { return true }
        if value["feature"] as? String == "selected-feature-install",
           DriverJobPolicy.strictTrue(value["persistent_write_phase_attempted"]), DriverJobPolicy.verifiedWrite(value) { return true }
        if finalAcceptance(value) { return true }
        if DriverJobPolicy.verifiedFeatureCheckpoint(value) { return true }
        return DriverJobPolicy.verifiedBackupTargetCheckpoint(value)
            && ["RUNTIME_BOUNDARY_REQUIRED", "ALL_TARGETS_VERIFIED_REBOOT_PENDING", "ALL_TARGETS_READBACK_RO_PENDING"].contains(value["status"] as? String ?? "")
    }
}

// User acknowledgement only; never substitutes for native boot/load proof.
struct ColdStartStepConfirmation {
    private(set) var started = false
    private(set) var completed = false
    var canComplete: Bool { started && !completed }
    mutating func reset() { started = false; completed = false }
    mutating func start() { if !completed { started = true } }
    @discardableResult mutating func complete() -> Bool {
        guard canComplete else { return false }
        completed = true
        return true
    }
}

enum BackupImportPresentation {
    static func summary(_ value: [String: Any]) -> String? {
        guard value["schema"] as? String == "a7m4-portable-import-progress/1",
              let phase = value["phase"] as? String else { return nil }
        let titles = ["PREPARING": "准备本地校验", "READ_OUTER_ARCHIVE": "读取备份包",
            "HASH_OUTER_ARCHIVE": "核对备份包哈希", "VERIFY_CORE_ARCHIVE": "校验核心备份",
            "VERIFY_SETTINGS": "校验完整设置", "VERIFY_NESTED_ARCHIVE": "校验嵌套资源包",
            "EXTRACT_SNAPSHOT": "提取本地快照", "VERIFY_IMPORTED_FILES": "核对导入文件",
            "COMPLETE": "数据处理完成，正在核对最终结果", "FAILED": "校验停止，正在整理失败报告"]
        guard var title = titles[phase] else { return nil }
        func number(_ key: String) -> Double? {
            guard let raw = value[key] as? NSNumber, CFGetTypeID(raw) != CFBooleanGetTypeID(),
                  raw.doubleValue.isFinite, raw.doubleValue >= 0, raw.doubleValue <= Double(1 << 40) else { return nil }
            return raw.doubleValue
        }
        if let done = number("objects_done"), let total = number("objects_total"), total > 0, done <= total {
            title += " · 本阶段 \(Int(done))／\(Int(total)) 项"
        } else if let done = number("bytes_done"), let total = number("bytes_total"), total > 0, done <= total {
            title += String(format: " · 本阶段 %.1f／%.1f MiB", done / 1048576, total / 1048576)
        }
        if let elapsed = number("elapsed_seconds") { title += " · 已用 \(Int(elapsed)) 秒" }
        return title
    }
}

final class AppDiagnostics: @unchecked Sendable {
    static let shared = AppDiagnostics()
    let sessionID = UUID().uuidString
    let directory: URL
    private let lock = NSLock()
    private var handle: FileHandle?
    private var bytes = 0
    private var segment = 0
    private var processRuns: [Int32: String] = [:]
    private let limit = 1024 * 1024

    private init() {
        directory = ProductIdentity.offlineQA ? ProductIdentity.qaRoot.appendingPathComponent("logs", isDirectory: true) :
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/A7M4 Toolbox", isDirectory: true)
        do {
            var parent = directory
            while parent.path != "/" {
                if (try? parent.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw CocoaError(.fileWriteInvalidFileName) }
                parent.deleteLastPathComponent()
            }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let info = try FileManager.default.attributesOfItem(atPath: directory.path)
            guard (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { throw CocoaError(.fileWriteNoPermission) }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            let path = directory.appendingPathComponent("app-\(sessionID).jsonl")
            let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
            handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        } catch { handle = nil }
        let os = ProcessInfo.processInfo.operatingSystemVersion
        record("app-start", ["build": ProductIdentity.iteration, "version": ProductIdentity.version, "system": ProcessInfo.processInfo.operatingSystemVersionString,
            "os_version": "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)", "log_available": handle != nil])
    }

    var available: Bool { lock.lock(); defer { lock.unlock() }; return handle != nil }
    static func isDiagnosticFile(_ file: URL) -> Bool {
        file.lastPathComponent.range(of: "^(app|run|job)-[0-9A-Fa-f-]{16,40}(-part-[0-9]{6})?\\.jsonl$", options: .regularExpression) != nil
    }

    static func clean(_ text: String) -> String {
        String(text.prefix(2048))
            .replacingOccurrences(of: "(?i)(password|secret|token|key)\\s*[=:]\\s*\\S+", with: "$1=[redacted]", options: .regularExpression)
            .replacingOccurrences(of: "(?i)\\b[0-9a-f]{32,}\\b", with: "[hex omitted]", options: .regularExpression)
    }
    func record(_ event: String, _ fields: [String: Any] = [:]) {
        lock.lock(); defer { lock.unlock() }
        guard handle != nil else { return }
        var value = fields
        value["event"] = event; value["session_id"] = sessionID
        value["time"] = ISO8601DateFormatter().string(from: Date())
        guard var data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), data.count < limit / 2 else { return }
        if bytes + data.count + 1 > limit {
            // Retain every prior segment; never truncate historical diagnostics.
            do {
                try handle?.synchronize(); try handle?.close(); handle = nil
                segment += 1
                let path = directory.appendingPathComponent("app-\(sessionID)-part-\(String(format: "%06d", segment)).jsonl")
                let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { return }
                handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); bytes = 0
            } catch { handle = nil; return }
        }
        data.append(10)
        try? handle?.write(contentsOf: data); bytes += data.count
        try? handle?.synchronize()
    }
    static func launch(_ child: Process, runID: String = UUID().uuidString) throws {
        let log = shared
        var args = child.arguments ?? []
        let isDriver = args.contains { $0.hasSuffix("/run_research.py") || $0.hasSuffix("/run_toolbox.py") }
        if isDriver { args += ["--diagnostic-run-id", runID]; child.arguments = args }
        let operation = args.firstIndex(of: "driver").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil }
            ?? args.firstIndex(where: { $0.hasSuffix("/run_research.py") }).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } ?? "local-helper"
        log.record("process-start", ["run_id": runID, "helper": child.executableURL?.lastPathComponent ?? "unknown", "operation": clean(operation), "argument_count": args.count, "administrator_authorization": args.contains("--session-authorize")])
        child.terminationHandler = { process in
            log.record("process-exit", ["run_id": runID, "exit_code": process.terminationStatus, "termination_reason": process.terminationReason == .uncaughtSignal ? "signal" : "exit"])
        }
        do {
            try child.run()
            log.lock.lock(); log.processRuns[child.processIdentifier] = runID; log.lock.unlock()
        } catch {
            log.record("process-launch-error", ["run_id": runID, "error": clean(error.localizedDescription)])
            throw error
        }
    }
    static func output(_ data: Data, child: Process) {
        let log = shared
        log.lock.lock(); let runID = log.processRuns.removeValue(forKey: child.processIdentifier) ?? "unknown"; log.lock.unlock()
        var fields: [String: Any] = ["run_id": runID, "bytes": data.count, "sha256": SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()]
        if let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            for key in ["schema", "status", "error", "version"] { if let text = value[key] as? String { fields[key] = clean(text) } }
        }
        log.record("restricted-process-output", fields)
    }
    func driverResult(_ value: [String: Any]?, runID: String, exitCode: Int32?, terminalConfirmed: Bool,
                      elevated: Bool, completionEvidence: String) {
        for key in ["native_dependencies", "dependency_probe"] {
            if let probe = value?[key] as? [String: Any] {
                record("native-dependency-probe", ["run_id": runID, "probe": probe])
            }
        }
        for key in ["host_error", "host_return_error"] {
            if let detail = value?[key] as? [String: Any] { record("host-observation-error", ["run_id": runID, "details": detail]) }
        }
        var fields: [String: Any] = ["run_id": runID, "driver_exit_code": exitCode.map { Int($0) } as Any? ?? NSNull(),
            "terminal_confirmed": terminalConfirmed, "administrator_authorization": elevated,
            "authorization_cancelled": value?["status"] as? String == "AUTH_CANCELLED", "completion_evidence": completionEvidence]
        for key in ["schema", "status", "error"] { if let text = value?[key] as? String { fields[key] = Self.clean(text) } }
        for key in ["camera_io", "complete", "normal_return_verified", "full_file_restore_complete"] {
            if let flag = value?[key] as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID() { fields[key] = flag }
        }
        record("driver-result", fields)
    }

    static func terminate(_ child: Process, reason: String) {
        let log = shared
        log.lock.lock(); let runID = log.processRuns[child.processIdentifier] ?? "unknown"; log.lock.unlock()
        log.record("process-termination-request", ["run_id": runID, "reason": reason])
        child.terminate()
    }
    func importJobLog(_ job: URL, runID: String) {
        let source = job.appendingPathComponent("capture/diagnostic.jsonl")
        guard let info = try? source.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey]), info.isSymbolicLink != true, info.isRegularFile == true, (info.fileSize ?? Int.max) <= limit,
              let data = try? Data(contentsOf: source) else { return }
        // Only our dedicated metadata log is copied, never receipts/packets.
        let path = directory.appendingPathComponent("job-\(runID).jsonl")
        let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try? file.write(contentsOf: data); try? file.close()
    }
    @MainActor func openFolder() { NSWorkspace.shared.open(directory) }
    @MainActor func export() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.zip]; panel.nameFieldStringValue = "A7M4-diagnostics-\(String(sessionID.prefix(8))).zip"
        guard panel.runModal() == .OK, let destination = panel.url else { record("diagnostic-export-cancelled"); return }
        do { try export(to: destination) }
        catch { record("diagnostic-export-failed", ["error": Self.clean(error.localizedDescription)]); let alert = NSAlert(error: error); alert.runModal() }
    }
    func export(to destination: URL) throws {
        lock.lock(); try? handle?.synchronize(); lock.unlock()
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("a7m4-diagnostics-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: temporary) }
        let content = temporary.appendingPathComponent("A7M4-diagnostics")
        try FileManager.default.createDirectory(at: content, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey])
            .filter { Self.isDiagnosticFile($0) }.sorted { ((try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) > ((try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) }
        var copied = 0
        for source in files {
            let values = try source.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey])
            guard values.isSymbolicLink != true, values.isRegularFile == true else { continue }
            let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
            guard (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { continue }
            try FileManager.default.copyItem(at: source, to: content.appendingPathComponent(source.lastPathComponent)); copied += 1
        }
        let metadata: [String: Any] = ["schema": "a7m4-diagnostic-export/1", "session_id": sessionID, "build": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "62", "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.5.1-alpha.62", "system": ProcessInfo.processInfo.operatingSystemVersionString, "log_count": copied, "raw_device_data_included": false, "automatic_upload": false, "scope": "all-currently-available-local-history", "previously_deleted_history_recoverable": false]
        try JSONSerialization.data(withJSONObject: metadata, options: [.prettyPrinted, .sortedKeys]).write(to: content.appendingPathComponent("summary.json"))
        let archive = temporary.appendingPathComponent("diagnostics.zip")
        let child = Process(); child.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        child.arguments = ["-c", "-k", "--norsrc", "--noextattr", "--noqtn", "--keepParent", content.path, archive.path]
        child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
        try child.run(); child.waitUntilExit()
        guard child.terminationStatus == 0 else { throw CocoaError(.fileWriteUnknown) }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: archive.path)
        if FileManager.default.fileExists(atPath: destination.path) { _ = try FileManager.default.replaceItemAt(destination, withItemAt: archive) }
        else { try FileManager.default.moveItem(at: archive, to: destination) }
        record("diagnostic-export-complete", ["log_count": copied])
    }
}

enum AppPrivateJobs {
    static func contains(_ path: URL, in root: URL) -> Bool {
        let base = root.standardizedFileURL.path, value = path.standardizedFileURL.path
        guard value == base || value.hasPrefix(base + "/") else { return false }
        var current = path.standardizedFileURL
        while current.path != "/" {
            if (try? current.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { return false }
            current.deleteLastPathComponent()
        }
        return true
    }
    static func create(support: URL, prefix: String) throws -> URL {
        guard !prefix.isEmpty, !prefix.contains("/"), !prefix.contains("\\"), !prefix.contains("\0"),
              contains(support, in: support) else { throw CocoaError(.fileWriteInvalidFileName) }
        let manager = FileManager.default
        for path in [support, support.appendingPathComponent("runs", isDirectory: true)] {
            try manager.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let info = try manager.attributesOfItem(atPath: path.path)
            guard info[.type] as? FileAttributeType == .typeDirectory,
                  (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(), contains(path, in: support) else {
                throw CocoaError(.fileWriteNoPermission)
            }
            // Tighten only our own application directories; never broaden mode.
            try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path.path)
        }
        let date = DateFormatter(); date.locale = Locale(identifier: "en_US_POSIX"); date.dateFormat = "yyyyMMdd-HHmmss"
        let job = support.appendingPathComponent("runs", isDirectory: true)
            .appendingPathComponent("\(prefix)-\(date.string(from: Date()))-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: job, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return job
    }

}

// Host execution evidence has its own identity, independent of the device
// transaction directory and its once-only capture output.
struct AppOperationRecords {
    let identifier: String
    let directory: URL
    let transactionJob: URL?
    var receiptURL: URL { directory.appendingPathComponent(identifier + "-run-receipt.json") }

    static func name(version: String, iteration: String, id: UUID) throws -> String {
        let allowed = "^[A-Za-z0-9._-]{1,32}$"
        guard version.range(of: allowed, options: .regularExpression) != nil,
              iteration.range(of: allowed, options: .regularExpression) != nil else { throw CocoaError(.fileWriteInvalidFileName) }
        return "v\(version)-\(id.uuidString.lowercased())"
    }
    private static func ownedDirectory(_ path: URL, within root: URL) throws {
        guard AppPrivateJobs.contains(path, in: root) else { throw CocoaError(.fileWriteNoPermission) }
        let manager = FileManager.default
        if !manager.fileExists(atPath: path.path) {
            try manager.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        let info = try manager.attributesOfItem(atPath: path.path)
        guard info[.type] as? FileAttributeType == .typeDirectory,
              (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { throw CocoaError(.fileWriteNoPermission) }
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path.path)
    }
    static func create(job: URL?, support: URL, version: String, iteration: String, id: UUID) throws -> AppOperationRecords {
        let name = try name(version: version, iteration: iteration, id: id)
        let root = try job ?? AppPrivateJobs.create(support: support, prefix: name)
        try ownedDirectory(root, within: support)
        let operations = root.appendingPathComponent("operations", isDirectory: true)
        try ownedDirectory(operations, within: root)
        let folder = operations.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return AppOperationRecords(identifier: name, directory: folder, transactionJob: job)
    }
    static func preflight(job: URL, version: String, iteration: String, id: UUID = UUID()) throws -> URL {
        let parent = job.appendingPathComponent("preflight", isDirectory: true)
        try ownedDirectory(parent, within: job)
        let folder = parent.appendingPathComponent(try name(version: version, iteration: iteration, id: id), isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return folder
    }
    private func write(_ data: Data, _ name: String) throws {
        let path = directory.appendingPathComponent(name)
        guard AppPrivateJobs.contains(path, in: directory) else { throw CocoaError(.fileWriteNoPermission) }
        try data.write(to: path, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }
    func begin(arguments: [String], version: String, iteration: String) throws {
        try write(JSONSerialization.data(withJSONObject: ["schema": "a7m4-app-operation-start/1", "operation_id": identifier,
            "version": version, "iteration": iteration, "arguments": arguments,
            "process_output_streams": "stdout-and-stderr-separated"], options: [.prettyPrinted, .sortedKeys]), "operation.json")
    }
    // A logging failure is secondary evidence. It cannot change a driver's
    // success, failure, safety state or original error returned to the caller.
    func finish(output: Data, stderr: Data = Data(), stderrOmittedBytes: Int = 0,
                result: [String: Any]?, receipt: [String: Any]) -> [String] {
        var warnings: [String] = []
        // Historical filename retained; new records contain protocol stdout only.
        do { try write(output, "combined.stdout.log") } catch { warnings.append("进程输出记录未能保存：\(error.localizedDescription)") }
        let retainedStderr = Data(stderr.suffix(1024 * 1024))
        do { try write(retainedStderr, "diagnostic.stderr.log") } catch { warnings.append("进程诊断记录未能保存：\(error.localizedDescription)") }
        if let result {
            do { try write(JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]), "driver-result.json") }
            catch { warnings.append("底层结果副本未能保存：\(error.localizedDescription)") }
        }
        var summary = receipt
        summary["operation_id"] = identifier
        summary["operation_record"] = "operations/\(identifier)/\(identifier)-run-receipt.json"
        summary["process_output_streams"] = "stdout-and-stderr-separated"
        summary["stderr_captured_bytes"] = retainedStderr.count
        summary["stderr_omitted_bytes"] = max(0, stderrOmittedBytes) + max(0, stderr.count - retainedStderr.count)
        let bytes: Data
        do {
            bytes = try JSONSerialization.data(withJSONObject: summary, options: [.prettyPrinted, .sortedKeys])
            try write(bytes, identifier + "-run-receipt.json")
        } catch {
            warnings.append("本次本地汇总未能保存：\(error.localizedDescription)")
            return warnings
        }
        if let job = transactionJob {
            let latest = job.appendingPathComponent("run-receipt.json")
            do {
                guard AppPrivateJobs.contains(latest, in: job) else { throw CocoaError(.fileWriteNoPermission) }
                if FileManager.default.fileExists(atPath: latest.path) {
                    let info = try FileManager.default.attributesOfItem(atPath: latest.path)
                    guard info[.type] as? FileAttributeType == .typeRegular,
                          (info[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                          (info[.referenceCount] as? NSNumber)?.intValue == 1,
                          ((info[.size] as? NSNumber)?.intValue ?? Int.max) <= 2 * 1024 * 1024 else { throw CocoaError(.fileWriteNoPermission) }
                    try write(Data(contentsOf: latest), "previous-latest.json")
                }
                // Only this small, validated latest-summary alias is mutable.
                // The previous alias and all per-operation evidence are kept.
                try bytes.write(to: latest, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: latest.path)
            } catch { warnings.append("最新汇总别名未能更新：\(error.localizedDescription)") }
        }
        return warnings
    }
}

struct FilterChoice: Identifiable, Codable, Equatable {
    var id: String
    var label: String
    var enabled: Bool
    var cube: String?
    var normalIcon: String?
    var selectedIcon: String?
    var playbackIcon: String?
    var preset: String
    var checkOnly: Bool
    var iconText: String? = nil
}

// Keep legacy fields decodable, but never admit their recipes or file paths to a
// new project. The four runtime positions have stable identities and do not move
// when a position is omitted from a particular export.
enum RestrictedFilterPolicy {
    static let recipes = ["st", "m9"]

    static var defaults: [FilterChoice] {
        (1...4).map { slot in
            FilterChoice(id: "slot-\(slot)", label: slot == 1 ? "M9" : "保持机内位置 \(slot)", enabled: slot == 1,
                         preset: slot == 1 ? "m9" : "st", checkOnly: false, iconText: slot == 1 ? "M9" : "ST")
        }
    }

    static func migrated(_ saved: [FilterChoice], preserveDisplaySelection: Bool = false) -> [FilterChoice] {
        var result = defaults
        for index in result.indices where index >= saved.count { result[index].enabled = false }
        for (index, old) in saved.prefix(4).enumerated() {
            var item = old
            item.id = "slot-\(index + 1)"
            // Names and artwork are display choices, independent of the recipe.
            if item.iconText == nil {
                item.iconText = ["po": "PO", "m9": "M9", "check-green": "CHK", "check-invert": "INV"][old.preset] ?? "ST"
            }
            let admittedM9 = old.preset == "m9" && index == 0
            item.preset = admittedM9 ? "m9" : "st"
            // Earlier drafts allowed M9 in other slots and PO/check recipes.
            // Never turn those saved choices into a request to clear a color.
            let admittedDisplay = preserveDisplaySelection && old.preset == "st" && old.cube == nil && !old.checkOnly
                && old.id == "slot-\(index + 1)"
            item.enabled = index == 0 && (admittedM9 || admittedDisplay) && old.enabled
            item.cube = nil
            item.checkOnly = false
            result[index] = item
        }
        return result
    }

    static func selectedSlots(_ filters: [FilterChoice]) throws -> [(slot: Int, item: FilterChoice)] {
        guard filters.count == 4 else { throw invalid("配置必须包含固定的四个位置。") }
        for (index, item) in filters.enumerated() {
            guard item.id == "slot-\(index + 1)", recipes.contains(item.preset),
                  (item.preset != "m9" || index == 0), item.cube == nil, !item.checkOnly else {
                throw invalid("本版仅在第 1 槽提供内置 M9；其他槽保持现有颜色。旧 CUBE 和其他配方须先迁移。")
            }
        }
        return filters.enumerated().compactMap { index, item in
            item.enabled ? (slot: index + 1, item: item) : nil
        }
    }

    private static func invalid(_ message: String) -> NSError {
        NSError(domain: "RestrictedFilters", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

enum DriverJobPolicy {
    static func strictTrue(_ value: Any?) -> Bool {
        guard let value = value as? NSNumber else { return false }
        return CFGetTypeID(value) == CFBooleanGetTypeID() && value.boolValue
    }
    static func strictFalse(_ value: Any?) -> Bool {
        guard let value = value as? NSNumber else { return false }
        return CFGetTypeID(value) == CFBooleanGetTypeID() && !value.boolValue
    }

    static func protectsDeviceProcess(_ arguments: [String]) -> Bool {
        guard arguments.first == "driver" else { return false }
        // An unknown future driver operation is protected until classified.
        return arguments.count < 2 || !["status", "doctor", "diagnostics-export", "selected-freeze", "selected-plan", "backup-target-plan", "backup-target-acceptance", "helpers", "validate-filters", "restore-plan", "restore-job-plan", "tail-restore-status", "original-restore-plan", "original-acceptance", "sound-gate-plan", "looks-plan", "sound-plan", "sound-scoped-plan", "sound-c-restore-plan", "features-plan", "feature-c-restore-plan", "portable-verify", "portable-import", "connection-check", "capture-inspect", "capture-export", "capture-adopt"].contains(arguments[1])
    }

    static func observesHostUSB(_ arguments: [String]) -> Bool {
        arguments.first == "driver" && arguments.count > 1 && ["connection-check", "capture-adopt"].contains(arguments[1])
    }

    static func backupCoordinatorReady(_ value: [String: Any]?) -> Bool {
        let readiness = value?["driver_readiness"] as? [String: Any]
        return value?["schema"] as? String == "a7m4-toolbox-status/1"
            && strictTrue(readiness?["usb_backup_coordinator_ready"])
    }

    static func captureObjectCount(_ value: [String: Any]) -> Int? {
        if value["schema"] as? String == "a7m4-toolbox-usb-backup/2",
           value["resource_profile"] as? String == "m4-602-six-language/1" { return 11 }
        if value["schema"] as? String == "a7m4-toolbox-usb-backup/1", value["resource_profile"] == nil { return 73 }
        return nil
    }

    static func verifiedBackup(_ value: [String: Any]?) -> Bool {
        guard let value, let count = captureObjectCount(value) else { return false }
        return true
            && value["status"] as? String == "VERIFIED_BACKUP"
            && strictTrue(value["complete"]) && strictTrue(value["verified"])
            && strictTrue(value["archive_verified"]) && strictTrue(value["stop_safe"])
            && strictTrue(value["normal_return_verified"])
            && value["expected_object_count"] as? Int == count
            && value["captured_object_count"] as? Int == count && value["stable_object_count"] as? Int == count
            && value["model"] as? String == "ILCE-7M4" && value["firmware_version"] as? String == "6.02"
            && (value["archive_sha256"] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
            && value["archive"] is String && value["snapshot_dir"] is String && value["receipt"] is String
    }

    static func verifiedBackupData(_ value: [String: Any]?) -> Bool {
        guard let value, let count = captureObjectCount(value) else { return false }
        let normal = strictTrue(value["normal_return_verified"])
        guard (normal && value["status"] as? String == "VERIFIED_BACKUP") ||
                (strictFalse(value["normal_return_verified"]) && value["status"] as? String == "VERIFIED_BACKUP_EXIT_UNCONFIRMED") else { return false }
        return ["complete", "verified", "archive_verified", "settings_capture_verified"].allSatisfy { strictTrue(value[$0]) }
            && ["expected_object_count", "captured_object_count", "stable_object_count"].allSatisfy { value[$0] as? Int == count }
            && (value["archive_sha256"] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
            && value["archive"] is String && value["receipt"] is String && value["snapshot_dir"] is String
    }

    static func captureReceipt(at path: URL) throws -> [String: Any] {
        let values = try path.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true, (values.fileSize ?? Int.max) <= 2 * 1024 * 1024 else {
            throw NSError(domain: "DeviceBackup", code: 3, userInfo: [NSLocalizedDescriptionKey: "本次读取收据缺失或格式不符。"])
        }
        let stream = try FileHandle(forReadingFrom: path)
        defer { try? stream.close() }
        let data = try stream.read(upToCount: 2 * 1024 * 1024 + 1) ?? Data()
        guard data.count <= 2 * 1024 * 1024,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              ["a7m4-toolbox-usb-backup/1", "a7m4-toolbox-usb-backup/2", "a7m4-toolbox-device-job/1", "a7m4-original-backup-restore-job/1", "a7m4-backup-target-job/1"].contains(value["schema"] as? String ?? "") else {
            throw NSError(domain: "DeviceBackup", code: 4, userInfo: [NSLocalizedDescriptionKey: "本次读取收据无法识别。"])
        }
        return value
    }

    static func verifiedEmptyFeatureAttempt(at capsule: URL) -> Bool {
        // A failed preflight can create the master before claiming any C.
        // Only this exact, terminal local receipt may release its preference
        // reference; missing/unknown/partial evidence always keeps originals.
        do {
            guard capsule.isFileURL, !capsule.pathComponents.contains("."), !capsule.pathComponents.contains(".."),
                  capsule.lastPathComponent == "feature-union-C-capsule.private.json",
                  capsule.deletingLastPathComponent().lastPathComponent == "capture" else { return false }
            var ancestor = capsule
            while ancestor.path != "/" {
                let info = try ancestor.resourceValues(forKeys: [.isSymbolicLinkKey])
                guard info.isSymbolicLink != true else { return false }
                ancestor.deleteLastPathComponent()
            }
            let receipt = capsule.deletingLastPathComponent().appendingPathComponent("job.private.json")
            let job = try captureReceipt(at: receipt)
            guard job["schema"] as? String == "a7m4-toolbox-device-job/1",
                  job["feature"] as? String == "fixed-feature-install",
                  job["receipt"] as? String == receipt.path,
                  let profile = job["profile"] as? String,
                  ["fl23", "custom1-m9", "all-current"].contains(profile),
                  strictFalse(job["simulation"]), strictFalse(job["complete"]), strictFalse(job["verified"]),
                  strictFalse(job["persistent_write_phase_attempted"]), strictFalse(job["union_C_restored"]),
                  strictFalse(job["E_F_gate_execution"]),
                  let body = job["body_binding"] as? [String: Any], !body.isEmpty,
                  let ref = job["C_capsule_ref"] as? [String: Any],
                  ref["path"] as? String == capsule.lastPathComponent, let size = ref["size"] as? Int,
                  size > 0, size <= 8 * 1024 * 1024, let digest = ref["sha256"] as? String else { return false }
            let returned = strictTrue(job["camera_io"]) && job["status"] as? String == "STOPPED_PREFLIGHT_NORMAL_RETURN"
                && ["normal_return_verified", "service_exit_confirmed", "stop_safe"].allSatisfy({ strictTrue(job[$0]) })
            let local = strictFalse(job["camera_io"]) && job["status"] as? String == "STOPPED_LOCAL"
                && ["normal_return_verified", "service_exit_confirmed", "stop_safe"].allSatisfy({ strictFalse(job[$0]) })
            guard returned || local else { return false }
            let info = try capsule.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard info.isRegularFile == true, info.isSymbolicLink != true, info.fileSize == size else { return false }
            let stream = try FileHandle(forReadingFrom: capsule)
            defer { try? stream.close() }
            let bytes = try stream.read(upToCount: 8 * 1024 * 1024 + 1) ?? Data()
            guard bytes.count == size,
                  SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == digest,
                  let master = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                  Set(master.keys) == Set(["schema", "profile", "firmware", "loader_sha256", "body_binding", "children",
                                           "revision", "capsule_sha256", "cache_restore", "E_F_restore_promised"]),
                  master["schema"] as? String == "a7m4-feature-union-C/1",
                  master["profile"] as? String == profile, master["firmware"] as? String == "6.02",
                  (master["loader_sha256"] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  (master["capsule_sha256"] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  strictFalse(master["E_F_restore_promised"]), master["cache_restore"] as? String == "NORMAL_REBUILD",
                  master["revision"] as? Int == 0, !strictFalse(master["revision"]),
                  let masterBody = master["body_binding"] as? [String: Any],
                  NSDictionary(dictionary: masterBody).isEqual(to: body),
                  let children = master["children"] as? [String: Any], children.isEmpty else { return false }
            return true
        } catch { return false }
    }

    static func validatedBackup(_ value: [String: Any]?, captureRoot: URL) throws -> [String: Any] {
        let receipt = captureRoot.appendingPathComponent("capture.private.json")
        let archive = captureRoot.appendingPathComponent("original.a7backup")
        let snapshot = captureRoot.appendingPathComponent("snapshot", isDirectory: true)
        let archiveValues = try archive.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        let snapshotValues = try snapshot.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard verifiedBackup(value), value?["archive"] as? String == archive.path,
              value?["snapshot_dir"] as? String == snapshot.path, value?["receipt"] as? String == receipt.path,
              archiveValues.isRegularFile == true, archiveValues.isSymbolicLink != true,
              archiveValues.fileSize == value?["archive_size"] as? Int,
              snapshotValues.isDirectory == true, snapshotValues.isSymbolicLink != true else {
            throw NSError(domain: "DeviceBackup", code: 1, userInfo: [NSLocalizedDescriptionKey: "本次备份路径或文件不符，尚未确认完整备份。"])
        }
        let saved = try captureReceipt(at: receipt)
        guard verifiedBackup(saved), saved["archive_sha256"] as? String == value?["archive_sha256"] as? String,
              saved["archive_size"] as? Int == value?["archive_size"] as? Int,
              saved["archive"] as? String == archive.path, saved["snapshot_dir"] as? String == snapshot.path,
              saved["receipt"] as? String == receipt.path else {
            throw NSError(domain: "DeviceBackup", code: 2, userInfo: [NSLocalizedDescriptionKey: "本次磁盘收据与 driver 结果不一致，尚未确认完整备份。"])
        }
        return saved
    }

    static func verifiedOriginalCheckpoint(_ value: [String: Any]?) -> Bool {
        guard let value, value["schema"] as? String == "a7m4-original-backup-restore-job/1",
              value["resource_profile"] as? String == "m4-602-six-language/1",
              strictTrue(value["camera_io"]), strictFalse(value["simulation"]),
              ["normal_return_verified", "service_exit_confirmed", "stop_safe"].allSatisfy({ strictTrue(value[$0]) }),
              let finalizer = value["finalizer"] as? [String: Any],
              ["exact_owned_cleanup_verified", "native_context_healthy", "safe_stop_allowed"].allSatisfy({ strictTrue(finalizer[$0]) }),
              strictTrue(finalizer["usr_readonly_verified"]) || strictTrue(finalizer["known_deferred_readonly"]) else { return false }
        let status = value["status"] as? String ?? ""
        if status == "RUNTIME_BOUNDARY_REQUIRED" { return strictFalse(value["complete"]) }
        guard ["ALL_TARGETS_VERIFIED_REBOOT_PENDING", "ALL_TARGETS_READBACK_RO_PENDING", "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE"].contains(status),
              strictTrue(value["file_targets_readback_verified"]),
              (value["verified_objects"] as? [[String: Any]])?.count == 11 else { return false }
        if status == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" {
            return strictTrue(value["post_boot_full_file_verification_complete"])
                && strictTrue((value["runtime_target_proof"] as? [String: Any])?["loaded_original_ap_verified"])
                && strictTrue(finalizer["usr_readonly_verified"])
        }
        return strictFalse(value["complete"])
    }

    static func verifiedBackupTargetCheckpoint(_ value: [String: Any]?) -> Bool {
        guard let value, value["schema"] as? String == "a7m4-backup-target-job/1",
              value["resource_profile"] as? String == "m4-602-six-language/1",
              value["model"] as? String == "ILCE-7M4", value["firmware"] as? String == "6.02",
              ["plan_id", "scope_plan_id"].allSatisfy({ (value[$0] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }),
              strictTrue(value["camera_io"]), strictFalse(value["simulation"]), strictFalse(value["complete"]),
              strictFalse(value["install_history_required"]), strictTrue(value["E_F_observation_only"]),
              strictFalse(value["restores_entire_original_files"]),
              ["normal_return_verified", "service_exit_confirmed", "stop_safe"].allSatisfy({ strictTrue(value[$0]) }),
              let target = value["backup_capture"] as? [String: Any],
              let body = value["body_binding"] as? [String: Any], !body.isEmpty,
              let targetBody = target["body_binding"] as? [String: Any], NSDictionary(dictionary: body).isEqual(to: targetBody),
              ["receipt_sha256", "archive_sha256"].allSatisfy({ (target[$0] as? String)?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }),
              let finalizer = value["finalizer"] as? [String: Any],
              ["exact_owned_cleanup_verified", "native_context_healthy", "safe_stop_allowed"].allSatisfy({ strictTrue(finalizer[$0]) }),
              strictTrue(finalizer["usr_readonly_verified"]) || strictTrue(finalizer["known_deferred_readonly"]) else { return false }
        let status = value["status"] as? String ?? ""
        if status == "RUNTIME_BOUNDARY_REQUIRED" { return true }
        guard ["ALL_TARGETS_VERIFIED_REBOOT_PENDING", "ALL_TARGETS_READBACK_RO_PENDING", "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE"].contains(status),
              strictTrue(value["file_targets_readback_verified"]), strictTrue(value["settings_C_verified"]),
              (value["verified_objects"] as? [[String: Any]])?.count == 11 else { return false }
        if status == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" {
            return strictTrue(value["post_boot_scope_verification_complete"])
                && strictTrue((value["runtime_target_proof"] as? [String: Any])?["C_loaded_verified"])
                && strictTrue(finalizer["usr_readonly_verified"])
        }
        return true
    }

    static func verifiedFeatureCheckpoint(_ value: [String: Any]?) -> Bool {
        guard let value, value["schema"] as? String == "a7m4-toolbox-device-job/1",
              value["feature"] as? String == "fixed-feature-C-restore",
              value["status"] as? String == "RESOURCE_RESTORE_BOUNDARY_REQUIRED",
              strictTrue(value["camera_io"]), strictFalse(value["simulation"]),
              strictFalse(value["complete"]), strictFalse(value["verified"]), strictFalse(value["union_C_restored"]),
              ["fl23", "custom1-m9", "all-current"].contains(value["profile"] as? String ?? ""),
              strictFalse(value["E_F_gate_execution"]), value["C_capsule_ref"] is [String: Any],
              let files = value["verified_objects"] as? [[String: Any]], files.count == 3,
              let readback = value["readback"] as? [String: Any],
              readback["validation_scope"] as? String == "C-D-only-E-F-observations/1",
              ["C_D_verified", "settings_C_D_verified", "E_F_observed"].allSatisfy({ strictTrue(readback[$0]) }),
              strictFalse(readback["F_gate_execution"]), strictFalse(readback["semantic_whole_target_verified"]),
              strictFalse(value["native_sequence_complete"]),
              ["normal_return_verified", "service_exit_confirmed", "stop_safe", "full_readback_verified"].allSatisfy({ strictTrue(value[$0]) }),
              let checkpoint = value["checkpoint"] as? [String: Any],
              checkpoint["stage"] as? String == "RESOURCE_RESTORE_BOUNDARY_REQUIRED",
              strictFalse(checkpoint["complete"]), strictFalse(checkpoint["union_C_restored"]),
              strictTrue(checkpoint["normal_MSC_required"]), strictTrue(checkpoint["requires_new_boot_evidence"]) else { return false }
        return true
    }

    static func verifiedWrite(_ value: [String: Any]?) -> Bool {
        if verifiedOriginalCheckpoint(value) { return true }
        if verifiedBackupTargetCheckpoint(value) { return true }
        if verifiedFeatureCheckpoint(value) { return true }
        guard let value, value["schema"] as? String == "a7m4-toolbox-device-job/1",
              ["VERIFIED_APPLIED", "VERIFIED_NO_CHANGE"].contains(value["status"] as? String ?? ""),
              strictTrue(value["camera_io"]), strictFalse(value["simulation"]),
              let files = value["verified_objects"] as? [[String: Any]], !files.isEmpty, files.count <= 100 else { return false }
        if value["feature"] as? String == "electronic-sound-gate",
           let readback = value["readback"] as? [String: Any], readback["validation_scope"] as? String == "C-D-only-E-F-observations/1" {
            guard strictTrue(readback["scoped_objects_read"]), readback["object_count"] as? Int == 11, strictTrue(readback["C_D_verified"]),
                  strictTrue(readback["settings_C_D_verified"]), strictTrue(readback["E_F_observed"]),
                  strictFalse(readback["F_gate_execution"]) else { return false }
        }
        if ["scoped-sound-first-install", "gate-sound-C-total-restore"].contains(value["feature"] as? String ?? "") {
            guard let readback = value["readback"] as? [String: Any],
                  readback["validation_scope"] as? String == "C-D-only-E-F-observations/1",
                  strictTrue(readback["objects3_read"]), strictTrue(readback["C_D_verified"]),
                  strictTrue(readback["settings_C_D_verified"]), strictTrue(readback["E_F_observed"]),
                  strictFalse(readback["F_gate_execution"]), strictFalse(readback["semantic_whole_target_verified"]),
                  files.count == 3,
                  Set(files.compactMap { $0["path"] as? String }) == Set(["post/ap.bin", "post/cp.bin", "post/bank.bin"]),
                  value["C_capsule_ref"] as? [String: Any] != nil else { return false }
        }
        if value["feature"] as? String == "selected-feature-install" {
            guard value["profile"] as? String == "selected",
                  let selection = value["selection"] as? [String: Any],
                  let frozen = selection["selection"] as? [String: Any],
                  frozen["schema"] as? String == "a7m4-selected-config/1",
                  selection["selection_sha256"] as? String == frozen["selection_sha256"] as? String,
                  DriverJobPolicy.strictFalse(value["E_F_gate_execution"]),
                  let baseline = value["original_baseline_proof"] as? [String: Any],
                  DriverJobPolicy.strictTrue(baseline["registered_C_D_verified"]),
                  DriverJobPolicy.strictFalse(baseline["whole_F_hash_admission"]),
                  let readback = value["readback"] as? [String: Any],
                  ["C_D_verified", "settings_C_D_verified", "E_F_observed"].allSatisfy({ strictTrue(readback[$0]) }),
                  strictFalse(readback["F_gate_execution"]), files.count == 3,
                  strictTrue(value["native_sequence_complete"]), strictTrue(value["complete"]), strictTrue(value["verified"]),
                  ["normal_return_verified", "service_exit_confirmed", "stop_safe", "full_readback_verified"].allSatisfy({ strictTrue(value[$0]) }),
                  let loaded = value["original_loaded_C_proof"] as? [String: Any],
                  ["C_loaded_verified", "cleanup_safe", "no_memory_write", "no_COW"].allSatisfy({ strictTrue(loaded[$0]) }),
                  loaded["boot_id"] as? String == value["boot_id"] as? String,
                  loaded["process_id"] as? Int == value["native_process_id"] as? Int,
                  value["selected_C_ref"] is [String: Any] else { return false }
        }
        if ["fixed-feature-install", "fixed-feature-C-restore"].contains(value["feature"] as? String ?? "") {
            guard ["fl23", "custom1-m9", "all-current"].contains(value["profile"] as? String ?? ""),
                  strictFalse(value["E_F_gate_execution"]), let readback = value["readback"] as? [String: Any],
                  readback["validation_scope"] as? String == "C-D-only-E-F-observations/1",
                  strictTrue(readback["C_D_verified"]), strictTrue(readback["settings_C_D_verified"]),
                  strictTrue(readback["E_F_observed"]), strictFalse(readback["F_gate_execution"]),
                  strictFalse(readback["semantic_whole_target_verified"]), value["C_capsule_ref"] is [String: Any] else { return false }
            if value["feature"] as? String == "fixed-feature-C-restore", !strictTrue(value["union_C_restored"]) { return false }
        }
        return ["complete", "verified", "full_readback_verified", "stop_safe", "normal_return_verified", "service_exit_confirmed", "native_sequence_complete"]
            .allSatisfy { strictTrue(value[$0]) }
    }

    static func validatedWrite(_ value: [String: Any]?, captureRoot: URL) throws -> [String: Any] {
        guard let value, verifiedWrite(value), value["receipt"] as? String == captureRoot.appendingPathComponent("job.private.json").path else {
            throw NSError(domain: "DeviceWrite", code: 1, userInfo: [NSLocalizedDescriptionKey: "本次写入未通过完整读回与退出核验。"])
        }
        let saved = try captureReceipt(at: captureRoot.appendingPathComponent("job.private.json"))
        guard NSDictionary(dictionary: saved).isEqual(to: value) else {
            throw NSError(domain: "DeviceWrite", code: 2, userInfo: [NSLocalizedDescriptionKey: "磁盘收据与本次写入结果不一致。"])
        }
        let files = saved["verified_objects"] as? [[String: Any]] ?? []
        var seen = Set<String>()
        for row in files {
            guard let relative = row["path"] as? String, relative.hasPrefix("post/"), !relative.contains("\\"),
                  relative.split(separator: "/", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
                  seen.insert(relative).inserted, let size = row["size"] as? Int, size >= 0,
                  (size > 0 || (value["feature"] as? String == "electronic-sound-gate" && (value["readback"] as? [String: Any])?["validation_scope"] as? String == "C-D-only-E-F-observations/1")), size <= 160 * 1024 * 1024,
                  let digest = row["sha256"] as? String else { throw CocoaError(.fileReadCorruptFile) }
            let path = captureRoot.appendingPathComponent(relative)
            var check = path
            while check.path != captureRoot.path {
                let info = try check.resourceValues(forKeys: [.isSymbolicLinkKey])
                guard info.isSymbolicLink != true else { throw CocoaError(.fileReadCorruptFile) }
                check.deleteLastPathComponent()
            }
            let info = try path.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard info.isRegularFile == true, info.fileSize == size else { throw CocoaError(.fileReadCorruptFile) }
            let file = try FileHandle(forReadingFrom: path)
            var hash = SHA256(), count = 0
            do {
                while let data = try file.read(upToCount: 1024 * 1024), !data.isEmpty { count += data.count; hash.update(data: data) }
                try file.close()
            } catch { try? file.close(); throw error }
            guard count == size, hash.finalize().map({ String(format: "%02x", $0) }).joined() == digest else {
                throw CocoaError(.fileReadCorruptFile)
            }
        }
        if value["feature"] as? String == "looks-install", files.count != 11 { throw CocoaError(.fileReadCorruptFile) }
        let isFeatures = ["fixed-feature-install", "fixed-feature-C-restore"].contains(saved["feature"] as? String ?? "")
        let unionName = isFeatures ? "feature-union-C-capsule.private.json" : "gate-sound-C-capsule.private.json"
        for (field, name) in [("gate_C_capsule_ref", "gate-C-capsule.private.json"), ("C_capsule_ref", unionName), ("selected_C_ref", "selected-union-C.private.json")] {
            if let ref = saved[field] as? [String: Any] {
                let path = captureRoot.appendingPathComponent(name)
                let info = try path.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
                guard ref["path"] as? String == name, let size = ref["size"] as? Int,
                      size > 0, size <= (isFeatures || field == "selected_C_ref" ? 8 : 2) * 1024 * 1024, info.isRegularFile == true,
                      info.isSymbolicLink != true, info.fileSize == size else { throw CocoaError(.fileReadCorruptFile) }
                let bytes = try Data(contentsOf: path)
                guard bytes.count == size,
                      SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == ref["sha256"] as? String else {
                    throw CocoaError(.fileReadCorruptFile)
                }
            }
        }
        return saved
    }
}

// Public plan commands use the exact frozen argument values selected for this click.
// This host-only check grants no write authority: the device driver still replans
// and checks fresh full preimages after authorization.
enum LocalApplyPreflight {
    static let operations = ["sound-gate": "sound-gate-plan", "looks": "looks-plan",
        "sound": "sound-plan", "restore": "restore-job-plan", "original-restore": "original-restore-plan",
        "sound-scoped": "sound-scoped-plan", "sound-c-restore": "sound-c-restore-plan",
        "features": "features-plan", "feature-c-restore": "feature-c-restore-plan",
        "selected-install": "selected-plan",
        "backup-target-restore": "backup-target-plan", "backup-target-verify": "backup-target-plan"]

    static func arguments(for arguments: [String], output: URL) throws -> [String]? {
        guard arguments.first == "driver", arguments.count > 1 else { return nil }
        let operation = arguments[1]
        guard let plan = operations[operation] else {
            if DriverJobPolicy.protectsDeviceProcess(arguments) && !["backup", "original-verify"].contains(operation) {
                throw failure("此设备操作尚未接入本地计划校验。")
            }
            return nil
        }
        let inputs: Set<String>
        let required: Set<String>
        switch operation {
        case "sound-gate": inputs = ["--capture", "--state", "--program-job", "--sound-job"]; required = ["--capture", "--state"]
        case "looks": inputs = ["--capture", "--config", "--native-project", "--program-job", "--sound-job"]; required = ["--capture", "--config"]
        case "sound": inputs = ["--capture", "--prepared", "--previous-job", "--program-job"]; required = ["--capture", "--prepared"]
        case "sound-scoped": inputs = ["--capture", "--prepared", "--gate-capsule"]; required = inputs
        case "sound-c-restore": inputs = ["--capture", "--capsule"]; required = inputs
        case "selected-install": inputs = ["--capture", "--selection", "--selection-sha256"]; required = inputs
        case "features": inputs = ["--capture", "--profile", "--native-project", "--prepared"]; required = ["--capture", "--profile"]
        case "feature-c-restore": inputs = ["--capture", "--capsule", "--previous-job"]; required = ["--capture", "--capsule"]
        case "restore": inputs = ["--capture", "--previous-job"]; required = inputs
        case "backup-target-restore": inputs = ["--capture", "--original-capture", "--previous-job"]; required = ["--capture", "--original-capture"]
        case "backup-target-verify": inputs = ["--capture", "--original-capture", "--previous-job"]; required = inputs.union(["--startup-confirmed"])
        default: inputs = ["--capture", "--original-capture", "--previous-job"]; required = ["--capture", "--original-capture"]
        }
        let executionValues: Set<String> = ["--output", "--compiler"]
        let executionFlags: Set<String> = ["--execute", "--battery-confirmed", "--msc-confirmed", "--ack-backup", "--ack-brick", "--ack-risk", "--ack-original", "--startup-confirmed"]
        var result = ["driver", plan], seen = Set<String>(), index = 2
        while index < arguments.count {
            let flag = arguments[index]
            if inputs.contains(flag) || executionValues.contains(flag) {
                guard index + 1 < arguments.count, !arguments[index + 1].hasPrefix("--"),
                      flag == "--program-job" || !seen.contains(flag) else { throw failure("本次应用参数缺失或重复。") }
                seen.insert(flag)
                if inputs.contains(flag) { result += [flag, arguments[index + 1]] }
                index += 2
            } else if executionFlags.contains(flag) {
                guard !seen.contains(flag) else { throw failure("本次应用参数重复。") }
                seen.insert(flag); index += 1
            } else { throw failure("本次应用包含尚未接入本地计划的参数。") }
        }
        guard required.isSubset(of: seen) else { throw failure("本地计划缺少当前备份或本次选择。") }
        if operation == "looks" || operation == "sound-gate" || operation == "original-restore" || operation == "backup-target-restore" || operation == "backup-target-verify" {
            result += ["--output", output.path]
        }
        return result
    }

    static func validate(_ value: [String: Any]?, arguments: [String]) throws {
        guard let value, arguments.count > 1 else { throw failure("本地计划没有返回可核验结果。") }
        let schema = value["schema"] as? String
        var accepted = false
        switch arguments[1] {
        case "sound-gate":
            accepted = schema == "a7m4-toolbox-gate-selection/1" && DriverJobPolicy.strictFalse((value["gate"] as? [String: Any])?["camera_io"])
        case "looks": accepted = schema == "a7m4-toolbox-looks-plan/2" && DriverJobPolicy.strictFalse(value["camera_io"])
        case "sound": accepted = schema == "a7m4-toolbox-product-sound-selection/1" && DriverJobPolicy.strictFalse(value["camera_io"])
        case "sound-scoped": accepted = schema == "a7m4-scoped-sound-selection/1" && DriverJobPolicy.strictFalse(value["camera_io"]) && DriverJobPolicy.strictFalse(value["E_F_gate_execution"])
        case "sound-c-restore": accepted = schema == "a7m4-gate-sound-C-restore-selection/1" && DriverJobPolicy.strictFalse(value["camera_io"]) && DriverJobPolicy.strictFalse(value["E_F_restored"])
        case "selected-install":
            func input(_ flag: String) -> String? {
                guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else { return nil }
                return arguments[index + 1]
            }
            if let path = input("--selection"), let confirmed = input("--selection-sha256"),
               confirmed.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil {
                let inputURL = URL(fileURLWithPath: path)
                let info = try inputURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
                guard info.isRegularFile == true, info.isSymbolicLink != true, (info.fileSize ?? Int.max) <= 2 * 1024 * 1024 else { throw failure("安装配置快照路径或大小不符。") }
                let bytes = try Data(contentsOf: inputURL)
                guard bytes.count <= 2 * 1024 * 1024,
                      let frozen = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw failure("安装配置快照无法读取。") }
                accepted = schema == "a7m4-selected-plan/1" && DriverJobPolicy.strictFalse(value["camera_io"])
                    && DriverJobPolicy.strictFalse(value["E_F_gate_execution"])
                    && DriverJobPolicy.strictTrue(value["baseline_registered_C_D_unchanged"])
                    && frozen["schema"] as? String == "a7m4-selected-config/1"
                    && value["selection_sha256"] as? String == confirmed && frozen["selection_sha256"] as? String == confirmed
                    && value["capture_receipt"] as? String == input("--capture")
            }
        case "features":
            if let index = arguments.firstIndex(of: "--profile"), index + 1 < arguments.count {
                let profile = arguments[index + 1]
                accepted = schema == "a7m4-fixed-feature-selection/1" && DriverJobPolicy.strictFalse(value["camera_io"])
                    && DriverJobPolicy.strictFalse(value["E_F_gate_execution"])
                    && ["fl23", "custom1-m9", "all-current"].contains(profile) && value["profile"] as? String == profile
            }
        case "feature-c-restore":
            accepted = schema == "a7m4-fixed-feature-restore-selection/1" && DriverJobPolicy.strictFalse(value["camera_io"])
                && ["fl23", "custom1-m9", "all-current"].contains(value["profile"] as? String ?? "")
        case "restore":
            let selection = value["selection"] as? [String: Any]
            accepted = DriverJobPolicy.strictFalse(value["camera_io"]) && (
                schema == "a7m4-toolbox-product-sound-inverse-selection/1" ||
                (value["feature"] as? String == "restore-sound-gate" && selection?["schema"] as? String == "a7m4-toolbox-gate-restore/1") ||
                (["restore-programs", "restore-resources"].contains(value["feature"] as? String ?? "") && selection?["schema"] as? String == "a7m4-toolbox-restore-stage/1"))
        case "backup-target-restore", "backup-target-verify":
            func input(_ flag: String) -> String? {
                guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else { return nil }
                return arguments[index + 1]
            }
            let resumed = input("--previous-job") != nil
            accepted = schema == (resumed ? "a7m4-backup-target-resume-scope/1" : "a7m4-backup-target-scope/1")
                && DriverJobPolicy.strictFalse(value["camera_io"]) && DriverJobPolicy.strictFalse(value["E_F_gate_execution"])
                && DriverJobPolicy.strictFalse(value["actual_dispatch_history_required"])
                && DriverJobPolicy.strictTrue(value["ready_for_execution"])
                && (value["blockers"] as? [Any])?.isEmpty == true
                && (value["current_capture"] as? [String: Any])?["receipt"] as? String == input("--capture")
                && (value["backup_capture"] as? [String: Any])?["receipt"] as? String == input("--original-capture")
                && ["NO_OP", "RESTORE_SUPPORTED_BACKUP_SCOPE"].contains(value["operation"] as? String ?? "")
        case "original-restore":
            accepted = schema == "a7m4-original-backup-diff/1" && DriverJobPolicy.strictFalse(value["camera_io"])
                && (value["blockers"] as? [Any])?.isEmpty == true && value["status"] as? String == "DIFF_VERIFIED_REQUIRES_EXPLICIT_EXECUTION"
        default: break
        }
        guard accepted else { throw failure("本地计划未通过校验，请查看报告；尚未请求管理员权限。") }
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "LocalApplyPreflight", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

enum DeviceAuthorization { case administrator, currentUser }

struct DeviceRunnerOutput {
    let data: Data
    let driverExitCode: Int32?
    let terminalConfirmed: Bool
}

enum ShortLivedDeviceRunner {
    static let exitMarker = "\n__A7M4_TOOLBOX_DRIVER_EXIT__="
    // Only in this GUI process's memory; reopening creates a fresh session and
    // the first operation must authenticate again. No password is retained.
    static let administratorSessionID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    static func command(python: URL, runner: URL, arguments: [String], authorization: DeviceAuthorization,
                        ownerUID: UInt32, ownerGID: UInt32, job: URL) -> (executable: URL, arguments: [String], elevated: Bool) {
        let owned = arguments + ["--job-owner-uid", String(ownerUID), "--job-owner-gid", String(ownerGID)]
        if authorization == .currentUser || geteuid() == 0 {
            return (python, ["-I", "-B", runner.path] + owned, false)
        }
        return (python, ["-I", "-B", runner.path, "--session-authorize", job.path, administratorSessionID,
                         String(getpid()), python.path, runner.path] + owned, true)
    }

    static func decode(_ data: Data, elevated: Bool, processExitCode: Int32) -> DeviceRunnerOutput {
        guard elevated else { return DeviceRunnerOutput(data: data, driverExitCode: processExitCode, terminalConfirmed: true) }
        guard let text = String(data: data, encoding: .utf8) else {
            return DeviceRunnerOutput(data: data, driverExitCode: nil, terminalConfirmed: false)
        }
        guard let range = text.range(of: exitMarker, options: .backwards),
              let code = Int32(text[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)),
              (0...255).contains(code), processExitCode == 0 else {
            // A Terminal bridge failure after launch cannot establish whether the
            // privileged command started or is still running.
            return DeviceRunnerOutput(data: data, driverExitCode: nil, terminalConfirmed: false)
        }
        return DeviceRunnerOutput(data: Data(text[..<range.lowerBound].utf8), driverExitCode: code, terminalConfirmed: true)
    }
}

// Host process I/O only. stderr is diagnostic data, never protocol authority.
struct DriverCapturedOutput {
    let stdout: Data
    let stderr: Data
    let stdoutBytes: Int
    let stderrBytes: Int
    let stdoutLimit: Int
    let stdoutReadError: String?
    let stderrReadError: String?
    var stdoutComplete: Bool { stdoutReadError == nil && stdoutBytes <= stdoutLimit }
    var protocolData: Data { stdoutComplete ? stdout : Data() }
    var stderrOmittedBytes: Int { max(0, stderrBytes - stderr.count) }
}

final class DriverProcessCapture: @unchecked Sendable {
    // Match the already bounded root session transport; do not change its wire.
    static let stdoutLimit = 16 * 1024 * 1024
    static let stderrLimit = 1024 * 1024
    private final class Channel: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        private var bytes = 0
        private var readError: String?
        func drain(_ handle: FileHandle, limit: Int, keepTail: Bool) {
            defer { try? handle.close() }
            do {
                while let chunk = try handle.read(upToCount: 65536), !chunk.isEmpty {
                    lock.lock()
                    bytes += chunk.count
                    if keepTail {
                        data.append(chunk)
                        if data.count > limit { data.removeFirst(data.count - limit) }
                    } else {
                        let room = max(0, limit - data.count)
                        data.append(contentsOf: chunk.prefix(room))
                    }
                    lock.unlock()
                }
            } catch {
                lock.lock(); readError = error.localizedDescription; lock.unlock()
            }
        }
        func snapshot() -> (Data, Int, String?) {
            lock.lock(); defer { lock.unlock() }
            return (data, bytes, readError)
        }
    }
    private let stdoutPipe = Pipe()
    private let stderrPipe = Pipe()
    private let out = Channel()
    private let err = Channel()
    private let readers = DispatchGroup()
    private var started = false
    init(process: Process) {
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
    }
    // Call immediately after successful launch, before awaiting the main actor.
    func begin() {
        precondition(!started); started = true
        readers.enter()
        DispatchQueue.global(qos: .utility).async { [self] in
            out.drain(stdoutPipe.fileHandleForReading, limit: Self.stdoutLimit, keepTail: false)
            readers.leave()
        }
        readers.enter()
        DispatchQueue.global(qos: .utility).async { [self] in
            err.drain(stderrPipe.fileHandleForReading, limit: Self.stderrLimit, keepTail: true)
            readers.leave()
        }
        try? stdoutPipe.fileHandleForWriting.close()
        try? stderrPipe.fileHandleForWriting.close()
    }
    func collect(_ process: Process) -> DriverCapturedOutput {
        precondition(started)
        readers.wait()
        process.waitUntilExit()
        let stdout = out.snapshot(), stderr = err.snapshot()
        return DriverCapturedOutput(stdout: stdout.0, stderr: stderr.0, stdoutBytes: stdout.1, stderrBytes: stderr.1,
            stdoutLimit: Self.stdoutLimit, stdoutReadError: stdout.2, stderrReadError: stderr.2)
    }
}

@MainActor final class DeviceOperationLifetime {
    static let shared = DeviceOperationLifetime()
    private var jobs = Set<UUID>()
    var active: Bool { !jobs.isEmpty }
    func begin(_ id: UUID) { jobs.insert(id) }
    func end(_ id: UUID) { jobs.remove(id) }
    func explainWait() {
        let alert = NSAlert()
        alert.messageText = "设备作业正在进行"
        alert.informativeText = "正在完成有界读取与退出。请等待本次作业结束后再关闭或退出应用；此处不会中途终止服务进程。"
        alert.addButton(withTitle: "等待作业结束")
        alert.runModal()
    }
}

@MainActor final class ToolboxAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        AppDiagnostics.shared.record("app-quit-request", ["device_operation_active": DeviceOperationLifetime.shared.active])
        guard DeviceOperationLifetime.shared.active else { return .terminateNow }
        DeviceOperationLifetime.shared.explainWait()
        return .terminateCancel
    }
}

private struct DeviceWindowCloseGuard: NSViewRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { context.coordinator.attach(view.window) }
        return view
    }
    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async { context.coordinator.attach(nsView.window) }
    }
    static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) { coordinator.detach() }

    @MainActor final class Coordinator: NSObject, NSWindowDelegate {
        weak var window: NSWindow?
        weak var previousDelegate: NSWindowDelegate?
        func attach(_ candidate: NSWindow?) {
            guard let candidate, candidate.delegate !== self else { return }
            detach()
            window = candidate
            previousDelegate = candidate.delegate
            candidate.delegate = self
        }
        func detach() {
            if window?.delegate === self { window?.delegate = previousDelegate }
            window = nil
            previousDelegate = nil
        }
        func windowShouldClose(_ sender: NSWindow) -> Bool {
            if DeviceOperationLifetime.shared.active {
                DeviceOperationLifetime.shared.explainWait()
                return false
            }
            return previousDelegate?.windowShouldClose?(sender) ?? true
        }
        override func responds(to selector: Selector!) -> Bool {
            super.responds(to: selector) || previousDelegate?.responds(to: selector) == true
        }
        override func forwardingTarget(for selector: Selector!) -> Any? {
            previousDelegate?.responds(to: selector) == true ? previousDelegate : super.forwardingTarget(for: selector)
        }
    }
}

struct ApplicationReview: Identifiable {
    let id = UUID()
    let feature: String
    let backupSummary: String
    var displayName: String {
        ["固定配置:fl23": "安装 FL2／FL3", "固定配置:custom1-m9": "安装自定义1 M9与当前显示",
         "固定配置:all-current": "安装全部功能与当前显示", "功能并集恢复": "恢复本轮功能／继续"][feature] ?? feature
    }
}

private struct NativePreviewJob {
    let config: [String: Any]
    let itemIDs: [Int: String]
    let name: String
}

private struct NativePreviewOutcome {
    var urls: [String: [String: URL]] = [:]
    var activeProject: URL?
    var error: String?
}

private func nativeAssetURL(_ root: URL, _ relative: String) throws -> URL {
    let parts = relative.split(separator: "/", omittingEmptySubsequences: false)
    guard !relative.hasPrefix("/"), !relative.contains("\\"), !relative.contains(":"),
          !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
        throw NSError(domain: "NativeIcons", code: 1, userInfo: [NSLocalizedDescriptionKey: "图标结果包含无效的相对路径。"])
    }
    let url = root.appendingPathComponent(relative)
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard attributes[.type] as? FileAttributeType == .typeRegular else {
        throw NSError(domain: "NativeIcons", code: 2, userInfo: [NSLocalizedDescriptionKey: "图标结果缺失，或不是普通文件。"])
    }
    return url
}

private func readNativeAssets(_ root: URL, itemIDs: [Int: String]) throws -> [String: [String: URL]] {
    let data = try Data(contentsOf: root.appendingPathComponent("manifest.json"))
    guard let manifest = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          manifest["schema"] as? String == "a7m4-native-icons-result/1",
          let assets = manifest["assets"] as? [[String: Any]] else {
        throw NSError(domain: "NativeIcons", code: 3, userInfo: [NSLocalizedDescriptionKey: "原生图标结果清单无效。"])
    }
    let roles = ["list-normal": "normal", "list-selected": "selected", "playback": "playback"]
    var urls: [String: [String: URL]] = [:]
    var seen = Set<String>()
    for asset in assets {
        guard let slot = asset["slot"] as? Int, let id = itemIDs[slot],
              let bank = asset["bank_variant"] as? String, ["23", "32"].contains(bank),
              let route = asset["route"] as? String, let role = roles[route] else {
            throw NSError(domain: "NativeIcons", code: 4, userInfo: [NSLocalizedDescriptionKey: "图标槽位或三态映射不符。"])
        }
        guard seen.insert("\(bank)-\(slot)-\(route)").inserted else {
            throw NSError(domain: "NativeIcons", code: 5, userInfo: [NSLocalizedDescriptionKey: "图标清单含重复映射。"])
        }
        for key in ["png", "raw", "compressed"] {
            guard let name = asset[key] as? String, let expected = asset["\(key)_sha256"] as? String else {
                throw NSError(domain: "NativeIcons", code: 6, userInfo: [NSLocalizedDescriptionKey: "图标缺少预览或原生资源身份。"])
            }
            let url = try nativeAssetURL(root, name)
            let bytes = try Data(contentsOf: url)
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            guard digest == expected else {
                throw NSError(domain: "NativeIcons", code: 7, userInfo: [NSLocalizedDescriptionKey: "图标资源与本次预览不一致，请重新生成。"])
            }
            if key == "png" { urls[id, default: [:]][bank == "23" ? role : "32-" + role] = url }
        }
    }
    guard seen.count == itemIDs.count * 6,
          itemIDs.values.allSatisfy({ urls[$0]?.count == 6 }) else {
        throw NSError(domain: "NativeIcons", code: 8, userInfo: [NSLocalizedDescriptionKey: "图标三态或两套资源不完整。"])
    }
    return urls
}

// A new job owns this copy. Only its existing manifest is replaced; the
// preview directory and the general create-only JSON writer remain untouched.
enum SelectedDisplaySnapshot {
    static func freeze(project: URL, to output: URL, displayName: String, nativeRow: [String: Any], itemID: String) throws -> URL {
        _ = try readNativeAssets(project, itemIDs: [1: itemID])
        let sourceBytes = try Data(contentsOf: project.appendingPathComponent("manifest.json"))
        guard !FileManager.default.fileExists(atPath: output.path),
              var manifest = try JSONSerialization.jsonObject(with: sourceBytes) as? [String: Any],
              let slots = manifest["slots"] as? [[String: Any]], slots.count == 1,
              slots[0]["slot"] as? Int == 1, nativeRow["slot"] as? Int == 1,
              let text = nativeRow["text"] as? String, slots[0]["text"] as? String == text else { throw CocoaError(.fileReadCorruptFile) }
        try FileManager.default.copyItem(at: project, to: output)
        let path = output.appendingPathComponent("manifest.json")
        guard try Data(contentsOf: path) == sourceBytes else { throw CocoaError(.fileReadCorruptFile) }
        manifest["toolbox_display"] = ["schema": "a7m4-custom1-display/1", "slot": 1,
            "display_name": displayName, "icon_text": text]
        manifest["output_dir"] = output.path
        let bytes = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
        try bytes.write(to: path, options: .atomic)
        _ = try readNativeAssets(output, itemIDs: [1: itemID])
        return output
    }
}

struct SoundClipEdit: Codable, Equatable {
    var startSeconds: Double = 0
    var endSeconds: Double? = nil
    var fadeInMS: Double = 0
    var fadeOutMS: Double = 0
}

struct UserChoices: Codable, Equatable {
    var filters: [FilterChoice]
    var filterPolicyVersion: Int? = nil
    var stNoticeAccepted: Bool = false
    var includeFL2 = true
    var includeFL3 = true
    var soundPreset = "factory"
    var soundFiles: [String: String] = [:]
    var shutterSeconds: Double = 0.125
    // Optional so preferences saved before this GUI control still decode intact.
    var kaShaSwitchDenominator: Int? = nil
    var volume: Double = 0.35
    var soundGainDB: Double? = nil
    var soundEdits: [String: SoundClipEdit]? = nil
    var recockEnabled: Bool? = nil
    var recockGapMS: Double? = nil
    var linkKaShaPairDelay: Bool? = nil
    var kaShaPairDelayMS: Double? = nil
    var includeCutoffCandidate: Bool? = nil
    var selectedSoundInstallMode: String? = nil
    var lastSelectedJob: String? = nil
    var desiredElectronicSoundEnabled: Bool? = nil
    var completedProgramJobs: [String]? = nil
    var lastSoundJob: String? = nil
    var lastGateCapsule: String? = nil
    var lastSoundCapsule: String? = nil
    var lastFeatureCapsule: String? = nil
    var lastFeatureCheckpoint: String? = nil
    var featureProgressFraction: Double? = nil
    var featureProgressProfile: String? = nil
    var featureMachineSeconds: Double? = nil
    var featureUserWaitSeconds: Double? = nil
    var featureWaitStartedAt: Date? = nil
    var featureCheckpointCount: Int? = nil
    var effectiveSoundGainDB: Double { soundGainDB ?? (volume > 0 ? max(-60, 20 * log10(volume)) : -60) }
    var effectiveRecockEnabled: Bool { recockEnabled ?? (soundPreset == "m9-recock") }
    var effectiveRecockGapMS: Double { recockGapMS ?? 40 }
    var effectiveLinkKaShaPairDelay: Bool { false }
    var effectiveKaShaPairDelayMS: Double { 20 }
    static let kaShaSwitchOptions = [8, 50]
    var effectiveKaShaSwitchDenominator: Int {
        guard let value = kaShaSwitchDenominator, Self.kaShaSwitchOptions.contains(value) else { return 50 }
        return value
    }
    var kaShaSwitchSeconds: Double { 1.0 / Double(effectiveKaShaSwitchDenominator) }
    static var initial: UserChoices {
        var value = UserChoices(filters: RestrictedFilterPolicy.defaults)
        value.filterPolicyVersion = 3
        value.soundGainDB = 0
        value.selectedSoundInstallMode = "prepared"
        value.kaShaSwitchDenominator = 8
        value.linkKaShaPairDelay = false; value.kaShaPairDelayMS = 20
        return value
    }
}

struct ReferenceLink: Identifiable {
    var id: String { title }
    var title: String
    var purpose: String
    var url: URL
}

private struct KaShaPreview {
    let revision: UUID
    let directory: URL
    let prepared: URL
    let urls: [String: URL]
    let manifest: [String: Any]
}
private struct KaShaPreviewOutcome {
    var preview: KaShaPreview?
    var error: String?
}

@MainActor final class ProductModel: ObservableObject {
    @Published var choices: UserChoices = .initial {
        didSet {
            saveChoices()
            players.forEach { $0.volume = 1 }
            if oldValue.filters != choices.filters { scheduleNativePreview() }
            if oldValue.shutterSeconds != choices.shutterSeconds { stopAudio() }
            if oldValue.includeCutoffCandidate != choices.includeCutoffCandidate { pinPlanFile = nil }
            if oldValue.soundPreset != choices.soundPreset || oldValue.soundFiles != choices.soundFiles ||
                oldValue.effectiveKaShaSwitchDenominator != choices.effectiveKaShaSwitchDenominator ||
                oldValue.effectiveSoundGainDB != choices.effectiveSoundGainDB || oldValue.soundEdits != choices.soundEdits ||
                oldValue.effectiveRecockEnabled != choices.effectiveRecockEnabled ||
                oldValue.effectiveRecockGapMS != choices.effectiveRecockGapMS ||
                oldValue.effectiveLinkKaShaPairDelay != choices.effectiveLinkKaShaPairDelay ||
                oldValue.effectiveKaShaPairDelayMS != choices.effectiveKaShaPairDelayMS {
                pinPlanFile = nil
                stopAudio()
                scheduleKaShaPreview()
            }
        }
    }
    @Published var running = false
    @Published var message = "可以先检查环境，或试听和编辑配置"
    @Published var error: String?
    @Published var recordWarning: String?
    @Published var report = ""
    @Published var output: URL?
    @Published var dependencyChecked = false
    @Published var dependencyOK = false
    @Published var usbDependenciesOK = false
    @Published private(set) var driverBackupCoordinationReady = false
    @Published var deviceJobRunning = false
    @Published var cameraObservation = "当前机身尚未读取"
    @Published var offlineSequenceStep = 0
    @Published var outputSpaceWarning: String?
    @Published var captureSummary = "尚无本次 11 对象备份记录"
    @Published var backupImportRunning = false
    @Published var backupImportSummary = ""
    @Published var backupImportFailed = false
    @Published var batteryConfirmed = false
    @Published var mscConfirmed = false
    @Published var selectedFilter = "slot-1" {
        didSet { if oldValue != selectedFilter { scheduleNativePreview() } }
    }
    @Published var localSnapshot: URL?
    @Published var selectedBackup: URL?
    @Published var backupVerified = false
    @Published var backupDataVerified = false
    @Published var dataCaptureReceipt: URL?
    @Published var connectionReady = false
    @Published var connectionSummary = "尚未做只读连接检查"
    @Published var captureReceipt: URL?
    @Published var originalRestoreReceipt: URL?
    @Published var originalRestoreArchive: URL?
    @Published var originalRestoreConfirmed = false
    @Published var originalRestoreLastJob: URL?
    @Published var originalRestorePhase = "NOT_STARTED"
    @Published var originalConsumerSafetyStage = ""
    private var restoreProgressFraction = 0.0
    private var readingCurrentForRestore = false
    private var restoreMachineSeconds = 0.0
    private var restoreWaitSeconds = 0.0
    private var restoreWaitStartedAt: Date?
    @Published var originalRestoreFailureJob: URL?
    @Published var originalStartupConfirmed = false
    @Published var originalColdStartRequired = false
    @Published var originalNamesAccepted = false
    @Published var originalSoundAccepted = false
    @Published var originalShootAccepted = false
    @Published var originalPlaybackAccepted = false
    @Published var previousDeviceJob: URL?
    @Published var audioMessage = "试听仅在这台 Mac 播放"
    @Published var audioPlaying = false
    @Published var soundBudgetSummary = ""
    @Published var pinImages: [String: URL] = [:]
    @Published var pinPlanFile: URL?
    @Published var pinCompiler: URL?
    @Published var kaShaPreparing = false
    @Published var kaShaError: String?
    @Published private var kaShaPreview: KaShaPreview?
    @Published var nativePreviewPending = false
    @Published var nativePreviewError: String?
    @Published var nativeIconURLs: [String: [String: URL]] = [:]
    @Published var nativeProject: URL?
    @Published var bankDirectory: URL?
    @Published var applicationReview: ApplicationReview?
    @Published var coldStartNotice = false
    @Published var coldStartFinalAcceptance = false
    @Published var coldStartForInstallation = false
    @Published var coldStartForSTProtection = false
    @Published var coldStartStepConfirmation = ColdStartStepConfirmation()
    private var coldStartInstallationVerified = false
    @Published var finalColdStartReady = false
    @Published var finalColdStartConfirmed = false
    @Published var fixedFeatureProfile = "fl23"
    @Published var selectedPreset = ""
    @Published var selectedSnapshotSummary = ""
    private var pendingSelectedJob: URL?
    private var pendingSelectedConfig: URL?
    private var pendingSelectedSHA256: String?
    @Published var featureStartupConfirmed = false
    @Published var progress = OperationProgress()
    @Published var timingProfile = "fl23"
    private var presentationTimer: Timer?
    private var nativePreviewTask: Task<Void, Never>?
    private var nativePreviewProcess: Process?
    private var nativePreviewRevision = UUID()
    private var nativePreviewReadyRevision: UUID?
    private var process: Process?
    private var stopped = false
    private var timedOut = false
    private var players: [AVAudioPlayer] = []
    private var pendingAudio: [DispatchWorkItem] = []
    private var auditionID = UUID()
    private var soundPreviewProcess: Process?
    private var groupPreviewProcess: Process?
    private var soundPreviewWorkspace: URL?
    private var kaShaTask: Task<Void, Never>?
    private var kaShaRevision = UUID()

    var canCaptureDeviceBackup: Bool {
        driverBackupCoordinationReady && usbDependenciesOK && batteryConfirmed && mscConfirmed && connectionReady && !running
    }
    var backupReadinessNote: String {
        if running { return "请等待当前操作完成。" }
        if !dependencyChecked { return "请先检查本地运行环境。" }
        if !usbDependenciesOK { return "本地 USB 依赖或 PMCA 源码校验尚未通过。" }
        if !driverBackupCoordinationReady { return "设备协调入口尚未就绪；当前不会检测或连接相机。" }
        if !connectionReady { return "请先点击“只读检查连接”，并完成 Mac 的“允许配件连接”。" }
        if !batteryConfirmed { return "请先确认相机电量充足。" }
        if !mscConfirmed { return "请先确认相机已设置为 MSC。" }
        return "只读备份入口已就绪。"
    }
    var fixedInstallReadinessNote: String {
        var missing: [String] = []
        if running { missing.append("等待当前操作完成") }
        if !connectionReady { missing.append("到“开始与备份”完成只读连接检查") }
        if !backupVerified || captureReceipt == nil {
            missing.append(backupDataVerified ? "备份数据已核验，但须确认当前 MSC 并接纳备份" : "选择并校验完整 .a7capture 备份，或创建新备份")
        }
        if choices.lastFeatureCapsule != nil { missing.append("先完成已有安装的功能恢复") }
        return missing.isEmpty ? "已满足安装前置条件；点击后仍须逐项确认备份与风险。" : "还需要：" + missing.joined(separator: "；") + "。"
    }
    var fixedRestoreReadinessNote: String {
        var missing: [String] = []
        if running { missing.append("等待当前操作完成") }
        if !connectionReady { missing.append("到“开始与备份”完成只读连接检查") }
        if !backupVerified || captureReceipt == nil { missing.append("导入并校验完整备份；未确认 MSC 的数据还须接纳") }
        if choices.lastFeatureCapsule == nil { missing.append("此旧恢复入口需要已保存的本轮安装原件；仅导入备份尚不能使用此入口") }
        if choices.lastFeatureCheckpoint != nil && !featureStartupConfirmed { missing.append("按提示冷启动并重新进入 MSC，然后勾选确认") }
        return missing.isEmpty ? "本轮恢复入口已就绪。" : "还需要：" + missing.joined(separator: "；") + "。"
    }
    var backupTargetPhaseText: String {
        if originalRestorePhase == "RUNTIME_BOUNDARY_REQUIRED" && originalConsumerSafetyStage == "ST_SAVED_PATCHES_RETAINED" {
            return ColdStartInstructions.stProtectionText
        }
        return ["NOT_STARTED": "尚未开始", "ORIGINAL_IMPORTED": "原始备份已校验，等待确认",
         "RUNTIME_BOUNDARY_REQUIRED": "本阶段已安全退出，等待按提示关开机后继续",
         "ALL_TARGETS_VERIFIED_REBOOT_PENDING": "功能区域已读回，等待关开机后的核验",
         "ALL_TARGETS_READBACK_RO_PENDING": "本阶段已读回，等待关开机后收尾",
         "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE": "机内读回与加载核验通过；请冷启动并验收功能",
         "USER_ACCEPTED_BACKUP_SCOPE_RESTORATION": "恢复与功能检查已完成",
         "STOP_UNKNOWN": "结果未知，请先导出日志并检查",
         "STOPPED_PREFLIGHT": "前置检查未通过，尚未完成恢复",
         "STOPPED_RESULT_DELIVERY": "结果交接未获确认，请先导出日志并检查"][originalRestorePhase] ?? "尚未完成，请查看诊断报告"
    }

    var backupTargetReadinessNote: String {
        var missing: [String] = []
        if originalRestorePhase == "STOP_UNKNOWN" || originalRestorePhase == "STOPPED_RESULT_DELIVERY" { return "上一恢复结果未知：请先导出全部历史日志并检查，不直接重试。" }
        if originalRestoreReceipt == nil { missing.append("选择并校验原始 .a7capture") }
        if !originalRestoreConfirmed { missing.append("确认备份保存于任何修改之前") }
        if !canCaptureDeviceBackup { missing.append(backupReadinessNote) }
        if originalRestoreLastJob != nil && !originalStartupConfirmed { missing.append("按恢复节点关开机并勾选确认") }
        return missing.isEmpty ? "已就绪；确认风险后将先自动读取当前状态。" : "还需要：" + missing.joined(separator: "；")
    }

    var resources: URL { Bundle.main.resourceURL! }
    var kit: URL { resources.appendingPathComponent("kit") }

    private func checkOutputSpace(_ args: [String], job: URL?) {
        let index = args.firstIndex(of: "--output")
        guard let output = index.flatMap({ $0 + 1 < args.count ? URL(fileURLWithPath: args[$0 + 1]) : nil }) ?? job else { return }
        var parent = output.standardizedFileURL
        while !FileManager.default.fileExists(atPath: parent.path) && parent.path != "/" { parent.deleteLastPathComponent() }
        parent = parent.resolvingSymlinksInPath()
        let reserve: Int64 = 1 << 30
        let operation = args.count > 1 && args[0] == "driver" ? args[1] : ""
        var required: Int64 = ["selected-install", "features", "backup-target-restore", "backup-target-verify", "original-verify", "sound", "sound-gate", "sound-scoped"].contains(operation) ? 2 << 30 : 512 << 20
        if let at = args.firstIndex(of: "--capture"), at+1 < args.count,
           let receipt = try? DriverJobPolicy.captureReceipt(at: URL(fileURLWithPath: args[at+1])),
           let rows = receipt["objects"] as? [String: [String: Any]] {
            required = max(required, 3 * rows.values.reduce(Int64(0)) { $0 + Int64(($1["size"] as? Int) ?? 0) })
        }
        do {
            let info = try FileManager.default.attributesOfFileSystem(forPath: parent.path)
            guard let free = (info[.systemFreeSize] as? NSNumber)?.int64Value else { throw CocoaError(.fileReadUnknown) }
            outputSpaceWarning = free < required + reserve ? "输出磁盘空间偏低：本次数据估计需 \(required / 1048576) MiB，另建议预留 1 GiB 日志空间。可继续操作；请及时释放空间。" : nil
            AppDiagnostics.shared.record("output-volume-space", ["available_bytes": free, "estimated_data_bytes": required, "extra_log_reserve_bytes": reserve, "warning": outputSpaceWarning != nil, "blocking": false])
        } catch {
            outputSpaceWarning = "无法读取输出磁盘剩余空间；建议确认数据空间，并额外预留 1 GiB 日志空间。"
            AppDiagnostics.shared.record("output-volume-space-unavailable", ["blocking": false, "extra_log_reserve_bytes": reserve])
        }
    }

    private func startPresentation(_ args: [String], job: URL?, wait: Bool) {
        presentationTimer?.invalidate()
        if let index = args.firstIndex(of: "--profile"), index+1 < args.count { timingProfile = args[index+1] }
        let backupRestore = readingCurrentForRestore || (args.count > 1 && ["backup-target-restore", "backup-target-verify"].contains(args[1]))
        let restoreArgs = ["driver", "backup-target-restore"] + (originalRestoreLastJob == nil ? [] : ["--previous-job", "saved"])
        let estimate = OperationEstimate.select(readingCurrentForRestore ? restoreArgs : args, profile: timingProfile)
        let resumed = backupRestore || estimate?.resumed == true
        let waitDate = backupRestore ? restoreWaitStartedAt : choices.featureWaitStartedAt
        let restartWait = resumed ? max(0,Date().timeIntervalSince(waitDate ?? Date())) : 0
        progress.begin(estimate, now: ProcessInfo.processInfo.systemUptime, wait: wait,
            saved: resumed ? (backupRestore ? restoreProgressFraction : choices.featureProgressFraction ?? 0) : 0,
            priorActive: resumed ? (backupRestore ? restoreMachineSeconds : choices.featureMachineSeconds ?? 0) : 0,
            priorWait: resumed ? (backupRestore ? restoreWaitSeconds : choices.featureUserWaitSeconds ?? 0)+restartWait : 0)
        if backupRestore { restoreWaitStartedAt = nil }
        AppDiagnostics.shared.record("operation-estimate-start", progress.metadata)
        presentationTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.running else { return }
                if self.backupImportRunning, args.count > 1, args[1] == "portable-import", let job {
                    let outputIndex = args.firstIndex(of: "--output")
                    let root = outputIndex.flatMap { $0 + 1 < args.count ? URL(fileURLWithPath: args[$0 + 1]) : nil } ?? job.appendingPathComponent("imported")
                    let path = root.appendingPathComponent("import-progress.json")
                    if let attributes = try? path.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]),
                       attributes.isRegularFile == true, attributes.isSymbolicLink != true,
                       let size = attributes.fileSize, size <= 4096,
                       let data = try? Data(contentsOf: path), data.count <= 4096,
                       let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let summary = BackupImportPresentation.summary(value) {
                        // Presentation never changes backup verification or device authority.
                        self.backupImportSummary = summary
                    }
                }
                var phase: String?
                if let job, let raw = try? Data(contentsOf: job.appendingPathComponent("authorization-phase.json")), raw.count < 4096,
                   let value = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
                   value["schema"] as? String == "a7m4-authorization-phase/1" { phase = value["phase"] as? String }
                let wasWaiting = self.progress.paused
                self.progress.tick(now: ProcessInfo.processInfo.systemUptime, authorization: phase)
                if wasWaiting && !self.progress.paused {
                    self.message = "授权已就绪。请保持电脑与相机连接；仅在应用明确提示冷启动时，按指引断开。"
                    AppDiagnostics.shared.record("authorization-ready", ["machine_timing_started": true])
                }
            }
        }
    }

    private func finishPresentation(ok: Bool, value: [String: Any]?, device: Bool) {
        presentationTimer?.invalidate(); presentationTimer = nil
        progress.finish(accepted: ok, verifiedComplete: !readingCurrentForRestore && (device ? DriverJobPolicy.strictTrue(value?["complete"]) && DriverJobPolicy.strictTrue(value?["verified"]) : ok),
            checkpoint: DriverJobPolicy.verifiedFeatureCheckpoint(value) || ColdStartInstructions.required(value), now: ProcessInfo.processInfo.systemUptime)
        AppDiagnostics.shared.record("operation-stage-timing", progress.metadata)
    }
    var assets: URL { kit.appendingPathComponent("a7m4/research/data/assets") }
    var support: URL {
        if ProductIdentity.offlineQA { return ProductIdentity.qaRoot.appendingPathComponent("support", isDirectory: true) }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("A7 IV Toolbox", isDirectory: true)
    }

    init() {
        _ = AppDiagnostics.shared
        let path = support.appendingPathComponent("preferences.json")
        if let data = try? Data(contentsOf: path), let saved = try? JSONDecoder().decode(UserChoices.self, from: data) {
            var migrated = saved
            migrated.filters = RestrictedFilterPolicy.migrated(saved.filters, preserveDisplaySelection: saved.filterPolicyVersion == 3)
            migrated.filterPolicyVersion = 3
            if migrated.selectedSoundInstallMode == nil {
                // Older 1/50 preferences described local audition only.
                migrated.selectedSoundInstallMode = "prepared"
                migrated.kaShaSwitchDenominator = 8
                migrated.linkKaShaPairDelay = false; migrated.kaShaPairDelayMS = 20
            }
            choices = migrated
            selectedFilter = migrated.filters.first?.id ?? "slot-1"
            saveChoices()
        }
        loadRestoreProgress()
        clearVerifiedEmptyFeatureReference()
        if choices.lastFeatureCheckpoint != nil {
            timingProfile = choices.featureProgressProfile ?? ""
            progress.begin(OperationEstimate.select(["driver", "feature-c-restore", "--previous-job", "saved"], profile: timingProfile),
                now: ProcessInfo.processInfo.systemUptime, wait: true, saved: choices.featureProgressFraction ?? 0,
                priorActive: choices.featureMachineSeconds ?? 0, priorWait: choices.featureUserWaitSeconds ?? 0)
            progress.fraction = min(0.95,max(0,choices.featureProgressFraction ?? 0)); progress.phase = "WAITING_RESTART"
        }
        if originalRestoreLastJob != nil && ["RUNTIME_BOUNDARY_REQUIRED", "ALL_TARGETS_VERIFIED_REBOOT_PENDING", "ALL_TARGETS_READBACK_RO_PENDING"].contains(originalRestorePhase) {
            progress.begin(OperationEstimate.select(["driver", "backup-target-restore", "--previous-job", "saved"], profile: ""),
                now: ProcessInfo.processInfo.systemUptime, wait: true, saved: restoreProgressFraction,
                priorActive: restoreMachineSeconds, priorWait: restoreWaitSeconds)
            progress.phase = "WAITING_RESTART"; progress.consumerSafetyStage = originalConsumerSafetyStage
            AppDiagnostics.shared.record("restore-checkpoint-loaded", progress.metadata)
        }
    }

    private func saveRestoreProgress() {
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var value = ["phase": originalRestorePhase, "schema": "a7m4-backup-target-ui/1", "resource_profile": "m4-602-six-language/1"]
            value["progress_fraction"] = String(restoreProgressFraction)
            value["machine_seconds"] = String(restoreMachineSeconds)
            value["wait_seconds"] = String(restoreWaitSeconds)
            value["wait_started_at"] = restoreWaitStartedAt.map { String($0.timeIntervalSince1970) }
            value["original_receipt"] = originalRestoreReceipt?.path
            value["original_archive"] = originalRestoreArchive?.path
            value["last_job"] = originalRestoreLastJob?.path
            value["failure_job"] = originalRestoreFailureJob?.path
            value["cold_start_required"] = originalColdStartRequired ? "true" : "false"
            value["consumer_safety_stage"] = originalConsumerSafetyStage
            let file = support.appendingPathComponent("original-restore-progress.json")
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch { self.error = "恢复进度未能保存：\(error.localizedDescription)" }
    }

    private func loadRestoreProgress() {
        guard let data = try? Data(contentsOf: support.appendingPathComponent("original-restore-progress.json")),
              let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: String],
              value["schema"] == "a7m4-backup-target-ui/1" else { return }
        originalRestoreReceipt = value["original_receipt"].map { URL(fileURLWithPath: $0) }
        originalRestoreArchive = value["original_archive"].map { URL(fileURLWithPath: $0) }
        originalRestoreLastJob = value["last_job"].map { URL(fileURLWithPath: $0) }
        originalRestoreFailureJob = value["failure_job"].map { URL(fileURLWithPath: $0) }
        originalRestorePhase = value["phase"] ?? "NOT_STARTED"
        originalColdStartRequired = value["cold_start_required"] == "true"
        if let receipt = originalRestoreLastJob.flatMap({ try? DriverJobPolicy.captureReceipt(at: $0) }) {
            finalColdStartReady = ColdStartInstructions.finalAcceptance(receipt)
            if DriverJobPolicy.verifiedBackupTargetCheckpoint(receipt) {
                originalConsumerSafetyStage = ColdStartInstructions.consumerStage(receipt)
            }
        }
        if let oldJob = originalRestoreLastJob,
           (try? DriverJobPolicy.captureReceipt(at: oldJob))?["resource_profile"] as? String != "m4-602-six-language/1" {
            originalRestoreFailureJob = oldJob; originalRestoreLastJob = nil
            originalRestorePhase = "LEGACY_CHECKPOINT_REPLAN_REQUIRED"
            originalRestoreReceipt = nil; originalRestoreArchive = nil; originalRestoreConfirmed = false
            originalColdStartRequired = false; finalColdStartReady = false
            message = "旧版本恢复记录已保留。请重新选择原始完整备份，并读取当前机身，按本版范围重新制定恢复计划。"
            AppDiagnostics.shared.record("legacy-restore-checkpoint-not-resumed", ["resource_profile": "m4-602-six-language/1", "history_preserved": true])
            return
        }
        finalColdStartConfirmed = false
        func finite(_ key: String) -> Double { let number = Double(value[key] ?? "") ?? 0; return number.isFinite ? max(0,number) : 0 }
        restoreProgressFraction = min(0.95,finite("progress_fraction"))
        restoreMachineSeconds = finite("machine_seconds"); restoreWaitSeconds = finite("wait_seconds")
        if let raw = value["wait_started_at"], let seconds = Double(raw), seconds.isFinite { restoreWaitStartedAt = Date(timeIntervalSince1970: seconds) }
    }

    private func saveChoices() {
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(choices)
            try data.write(to: support.appendingPathComponent("preferences.json"), options: .atomic)
        } catch { self.error = "本地配置未能保存：\(error.localizedDescription)" }
    }

    func file(_ title: String, types: [UTType]? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let types { panel.allowedContentTypes = types }
        return panel.runModal() == .OK ? panel.url : nil
    }

    func folder(_ title: String) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    func newJob(_ prefix: String) throws -> URL? {
        try AppPrivateJobs.create(support: support, prefix: prefix)
    }

    func revealBackup() {
        if let path = selectedBackup { NSWorkspace.shared.activateFileViewerSelecting([path]) }
    }

    func exportAllDiagnostics() {
        guard !running else { return }
        let panel = NSSavePanel(); panel.allowedContentTypes = [.zip]
        panel.title = "导出诊断报告"
        panel.nameFieldStringValue = "A7M4-history-\(ProductIdentity.iteration).zip"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            error = "请选择新的 ZIP 文件名，以保留已有日志包。"; return
        }
        run(["driver", "diagnostics-export", "--output", destination.path],
            title: "正在整理全部仍存在的历史日志和安全诊断报告…", authorization: .currentUser) { ok, _ in
            if ok {
                self.message = "全部仍存在的历史日志和安全诊断报告已导出；旧版已删除的记录无法找回。"
                NSWorkspace.shared.activateFileViewerSelecting([destination])
            }
        }
    }

    private func writeJSON(_ value: Any, to path: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: path, options: .withoutOverwriting)
    }

    func run(_ arguments: [String], title: String, job: URL? = nil,
             authorization: DeviceAuthorization = .administrator, completion: ((Bool, [String: Any]?) -> Void)? = nil) {
        guard !running else { return }
        do {
            // Validation precedes even the host-only read of private materials.
            guard validateRunInputs(arguments, job: job) else { return }
            guard try LocalApplyPreflight.arguments(for: arguments,
                output: support.appendingPathComponent("unused-plan")) != nil else {
                runCommand(arguments, title: title, job: job, authorization: authorization, completion: completion)
                return
            }
            guard let job else { return }
            let local = try AppOperationRecords.preflight(job: job, version: ProductIdentity.version, iteration: ProductIdentity.iteration)
            let plan = try LocalApplyPreflight.arguments(for: arguments, output: local.appendingPathComponent("plan"))!
            runCommand(plan, title: "正在使用当前备份核对本次应用计划，尚未请求管理员权限…",
                job: local, authorization: .currentUser) { ok, result in
                guard ok else {
                    self.message = "本地计划未通过，尚未请求管理员权限；请查看报告。"
                    return
                }
                do {
                    try LocalApplyPreflight.validate(result, arguments: arguments)
                    try self.writeJSON(result!, to: local.appendingPathComponent("plan-result.json"))
                    if let profile = result?["profile"] as? String, ["fl23", "custom1-m9", "all-current"].contains(profile) { self.timingProfile = profile }
                    // The same argument array is used even if a UI selection changes
                    // while planning. The root driver independently repeats all checks.
                    self.runCommand(arguments, title: title, job: job, authorization: authorization, completion: completion)
                } catch {
                    self.message = "本地计划未通过，尚未请求管理员权限。"
                    self.error = error.localizedDescription
                }
            }
        } catch {
            self.message = "本地计划尚未开始，未请求管理员权限。"
            self.error = error.localizedDescription
        }
    }

    private func validateRunInputs(_ arguments: [String], job: URL?) -> Bool {
        let deviceJob = DriverJobPolicy.protectsDeviceProcess(arguments)
        guard !deviceJob || job != nil else { error = "设备作业必须使用本次新建的私有目录。"; return false }
        if deviceJob {
            guard let job, AppPrivateJobs.contains(job, in: support.appendingPathComponent("runs", isDirectory: true)) else {
                error = "设备作业只能使用应用私有工作区。请重新创建本次作业。"; return false
            }
            let privateFlags = ["--capture", "--original-capture", "--output", "--prepared", "--config", "--native-project", "--program-job", "--sound-job", "--previous-job", "--gate-capsule", "--capsule"]
            for (index, argument) in arguments.enumerated() where privateFlags.contains(argument) {
                guard index + 1 < arguments.count,
                      AppPrivateJobs.contains(URL(fileURLWithPath: arguments[index + 1]), in: support) else {
                    error = "此旧材料位于应用私有工作区之外。请先在应用中重新导入完整备份或生成本次材料，再执行设备操作。"; return false
                }
            }
        }
        return true
    }

    private func runCommand(_ arguments: [String], title: String, job: URL? = nil,
             authorization: DeviceAuthorization = .administrator, completion: ((Bool, [String: Any]?) -> Void)? = nil) {
        if ProductIdentity.offlineQA && (DriverJobPolicy.protectsDeviceProcess(arguments) || DriverJobPolicy.observesHostUSB(arguments)) {
            error = "离线界面演示禁止设备操作或 USB 宿主枚举。"; return
        }
        guard !running, validateRunInputs(arguments, job: job) else { return }
        let deviceJob = DriverJobPolicy.protectsDeviceProcess(arguments)
        recordWarning = nil
        let operationID = UUID()
        let records: AppOperationRecords
        do {
            records = try AppOperationRecords.create(job: job, support: support, version: ProductIdentity.version,
                iteration: ProductIdentity.iteration, id: operationID)
            try records.begin(arguments: arguments, version: ProductIdentity.version, iteration: ProductIdentity.iteration)
        } catch {
            self.error = "本地操作记录尚未建立，未启动命令：\(error.localizedDescription)"
            completion?(false, nil)
            return
        }
        if deviceJob { DeviceOperationLifetime.shared.begin(operationID) }
        running = true
        deviceJobRunning = deviceJob
        if deviceJob { connectionReady = false }
        stopped = false
        timedOut = false
        error = nil
        report = ""
        message = title
        output = job
        let python = resources.appendingPathComponent("python/bin/python3")
        let runner = kit.appendingPathComponent("run_research.py")
        let cwd = kit
        if deviceJob { message = "首次相机操作请完成管理员授权；本次打开期间后续操作复用授权，请等待作业结束" }
        let start = Date()
        let ownerUID = getuid()
        let jobAttributes = job.flatMap { try? FileManager.default.attributesOfItem(atPath: $0.path) }
        let ownerGID = (jobAttributes?[.groupOwnerAccountID] as? NSNumber)?.uint32Value ?? getgid()
        let launch = deviceJob ? ShortLivedDeviceRunner.command(python: python, runner: runner, arguments: arguments,
            authorization: authorization, ownerUID: ownerUID, ownerGID: ownerGID, job: job!) :
            (executable: python, arguments: ["-I", "-B", runner.path] + arguments, elevated: false)
        checkOutputSpace(arguments, job: job)
        startPresentation(arguments, job: job, wait: deviceJob && launch.elevated)
        Task.detached {
            do {
                let child = Process()
                child.executableURL = launch.executable
                child.arguments = launch.arguments
                child.currentDirectoryURL = cwd
                child.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
                let capture = DriverProcessCapture(process: child)
                try AppDiagnostics.launch(child, runID: operationID.uuidString)
                capture.begin()
                await MainActor.run {
                    self.process = child
                    if self.stopped && !deviceJob { AppDiagnostics.terminate(child, reason: "cancel-or-timeout") }
                }
                if !deviceJob {
                    DispatchQueue.global().asyncAfter(deadline: .now() + 300) {
                        if child.isRunning {
                            Task { @MainActor in self.timedOut = true }
                            AppDiagnostics.terminate(child, reason: "timeout")
                            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                                if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) }
                            }
                        }
                    }
                }
                let channels = capture.collect(child)
                let data = channels.stdout
                AppDiagnostics.output(data, child: child)
                AppDiagnostics.shared.record("restricted-process-channels", ["run_id": operationID.uuidString,
                    "stdout_bytes": channels.stdoutBytes, "stdout_complete": channels.stdoutComplete,
                    "stderr_bytes": channels.stderrBytes, "stderr_captured_bytes": channels.stderr.count,
                    "stderr_omitted_bytes": channels.stderrOmittedBytes,
                    "stdout_read_error": channels.stdoutReadError as Any? ?? NSNull(),
                    "stderr_read_error": channels.stderrReadError as Any? ?? NSNull()])
                if let job { AppDiagnostics.shared.importJobLog(job, runID: operationID.uuidString) }
                let decoded = ShortLivedDeviceRunner.decode(channels.protocolData, elevated: launch.elevated, processExitCode: child.terminationStatus)
                var resultData = decoded.data
                var completionEvidence = launch.elevated ? "driver-exit-marker" : "direct-process-exit"
                if deviceJob && !decoded.terminalConfirmed, let job {
                    AppDiagnostics.shared.record("authorization-channel-unknown", ["run_id": operationID.uuidString, "launcher_exit_code": child.terminationStatus])
                    await MainActor.run {
                        self.process = nil
                        self.message = "授权执行通道状态未知，正在等待最终收据；不会终止设备任务"
                        self.report = String(decoding: data, as: UTF8.self)
                    }
                    // Only the root driver's final ownership return makes its
                    // private terminal receipt readable by this GUI user. Do
                    // not infer camera_io=false or release the close/quit guard
                    // from a Terminal bridge error while a root child may still run.
                    let receipt = job.appendingPathComponent(arguments.dropFirst().first == "backup" ? "capture/capture.private.json" : "capture/job.private.json")
                    while true {
                        if let attributes = try? FileManager.default.attributesOfItem(atPath: receipt.path),
                           (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == ownerUID,
                           let value = try? DriverJobPolicy.captureReceipt(at: receipt),
                           Self.isTerminalOwnedReceipt(value) {
                            resultData = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
                            completionEvidence = "returned-owned-terminal-receipt"
                            break
                        }
                        try await Task.sleep(nanoseconds: 1_000_000_000)
                    }
                }
                let text = String(decoding: resultData, as: UTF8.self)
                let object = (try? JSONSerialization.jsonObject(with: resultData)) as? [String: Any]
                AppDiagnostics.shared.driverResult(object, runID: operationID.uuidString, exitCode: decoded.driverExitCode,
                    terminalConfirmed: decoded.terminalConfirmed, elevated: launch.elevated, completionEvidence: completionEvidence)
                let finalCompletionEvidence = completionEvidence
                await MainActor.run {
                    let processOK = (decoded.driverExitCode == 0 ||
                        (finalCompletionEvidence == "returned-owned-terminal-receipt" && (DriverJobPolicy.verifiedBackup(object) || DriverJobPolicy.verifiedWrite(object))))
                        && !self.stopped && !self.timedOut && object != nil
                    let verifiedDeviceResult = job.map {
                        if Array(arguments.prefix(2)) == ["driver", "backup"] {
                            return (try? DriverJobPolicy.validatedBackup(object, captureRoot: $0.appendingPathComponent("capture"))) != nil
                        }
                        return (try? DriverJobPolicy.validatedWrite(object, captureRoot: $0.appendingPathComponent("capture"))) != nil
                    } == true
                    let ok = processOK && (!deviceJob || verifiedDeviceResult)
                    self.finishPresentation(ok: ok, value: object, device: deviceJob)
                    if ok && deviceJob && DriverJobPolicy.strictTrue(object?["camera_io"]),
                       let identity = object?["device_identity_observation"] as? [String: Any], DriverJobPolicy.strictTrue(identity["verified"]),
                       identity["model"] as? String == "ILCE-7M4", identity["firmware_version"] as? String == "6.02" {
                        self.cameraObservation = "最近一次真实读取：ILCE-7M4 · 6.02（支持的构建已核验）"
                    }
                    if deviceJob { self.connectionReady = DriverJobPolicy.strictTrue(object?["normal_return_verified"]) }
                    self.running = false
                    self.deviceJobRunning = false
                    DeviceOperationLifetime.shared.end(operationID)
                    self.process = nil
                    self.report = text
                    if deviceJob {
                        self.message = object?["status"] as? String == "AUTH_DEPENDENCIES_NOT_READY" ? "管理员后台依赖未就绪，未发送相机协议请求" :
                            object?["status"] as? String == "AUTH_CANCELLED" ? "系统授权已取消，未启动设备命令" :
                            ok ? (arguments.dropFirst().first == "backup" ? "完整备份与服务退出已核验，原件保存在本机" : "写入与完整读回已核验；请按提示关开机并检查功能") :
                            object?["status"] as? String == "FAILED_PARTIAL" ? "本次读取未完整完成，partial 原件和收据已保留" :
                            "设备作业结果未通过完整核验，请查看报告"
                    } else {
                        self.message = ok ? "已完成，结果保存在本机" : self.stopped ? "已停止，已有本地文件已保留" : self.timedOut ? "任务超时，已有本地文件已保留" : "未完成，请查看提示或诊断报告"
                    }
                    if !ok && !self.stopped && !self.timedOut && object?["status"] as? String != "AUTH_CANCELLED" {
                        self.error = object?["error"] as? String ?? (deviceJob ? "进程退出不代表设备作业已完整完成；本次结果未通过核验。" : "这次操作没有完成，诊断报告已保留。")
                    }
                    do {
                        let clock = ISO8601DateFormatter()
                        let fallback = deviceJob ? "UNKNOWN_DEVICE_RESULT" : self.stopped ? "STOPPED_BY_USER" : self.timedOut ? "TIMED_OUT" : ok ? "COMPLETED_LOCAL" : "STOPPED_LOCAL_INPUT"
                        let receipt: [String: Any] = [
                            "run_id": operationID.uuidString, "schema": "a7m4-app-job/2", "command": arguments.first ?? "", "arguments": arguments,
                            "status": object?["status"] as? String ?? fallback, "accepted_result": ok,
                            "driver_error": object?["error"] ?? NSNull(),
                            "started_at": clock.string(from: start), "finished_at": clock.string(from: Date()),
                            "exit_code": decoded.driverExitCode.map { Int($0) } as Any? ?? NSNull(),
                            "launcher_exit_code": child.terminationStatus, "completion_evidence": finalCompletionEvidence,
                            "stdout_complete": channels.stdoutComplete, "stdout_bytes": channels.stdoutBytes,
                            "stderr_bytes": channels.stderrBytes, "stderr_omitted_bytes": channels.stderrOmittedBytes,
                            "administrator_authorization": launch.elevated,
                            "camera_io": object?["camera_io"] ?? NSNull(),
                            "verified": object?["verified"] ?? NSNull(), "complete": object?["complete"] ?? NSNull(),
                            "stop_safe": object?["stop_safe"] ?? NSNull(), "network_io": object?["network_io"] ?? NSNull(),
                            "internet_uploads": object?["internet_uploads"] ?? NSNull(),
                            "result_schema": object?["schema"] ?? NSNull(), "device_process_protected": deviceJob
                            , "presentation_timing": self.progress.metadata
                        ]
                        let warnings = records.finish(output: data, stderr: channels.stderr, stderrOmittedBytes: channels.stderrOmittedBytes,
                            result: object, receipt: receipt)
                        if !warnings.isEmpty {
                            self.recordWarning = warnings.joined(separator: "\n")
                            AppDiagnostics.shared.record("operation-record-warning", ["run_id": operationID.uuidString,
                                "operation_id": records.identifier, "warnings": warnings])
                        }
                    }
                    completion?(ok, object)
                }
            } catch {
                await MainActor.run {
                    self.finishPresentation(ok: false, value: nil, device: deviceJob)
                    self.running = false
                    self.deviceJobRunning = false
                    DeviceOperationLifetime.shared.end(operationID)
                    self.process = nil
                    let launchError = error.localizedDescription
                    let warnings = records.finish(output: Data(), result: nil, receipt: ["status": "LAUNCH_FAILED",
                        "accepted_result": false, "driver_error": launchError, "run_id": operationID.uuidString])
                    if !warnings.isEmpty { self.recordWarning = warnings.joined(separator: "\n") }
                    self.message = "未能开始"
                    self.error = launchError
                    completion?(false, nil)
                }
            }
        }
    }

    nonisolated private static func isTerminalOwnedReceipt(_ value: [String: Any]) -> Bool {
        if DriverJobPolicy.verifiedBackup(value) { return true }
        if value["schema"] as? String == "a7m4-backup-target-job/1" {
            return DriverJobPolicy.verifiedBackupTargetCheckpoint(value) || ["STOP_UNKNOWN", "STOPPED_PREFLIGHT", "STOPPED_RESULT_DELIVERY"].contains(value["status"] as? String ?? "")
        }
        if value["schema"] as? String == "a7m4-original-backup-restore-job/1" {
            return DriverJobPolicy.verifiedOriginalCheckpoint(value) || ["STOP_UNKNOWN", "STOPPED_PREFLIGHT", "STOPPED_RESULT_DELIVERY"].contains(value["status"] as? String ?? "")
        }
        if value["schema"] as? String == "a7m4-toolbox-device-job/1" {
            return ["VERIFIED_APPLIED", "VERIFIED_NO_CHANGE", "VERIFIED_DISK_TARGETS_ADOPTION_PENDING", "RESOURCE_RESTORE_BOUNDARY_REQUIRED", "STOP_UNKNOWN", "STOPPED_LOCAL", "STOPPED_PREFLIGHT_NORMAL_RETURN", "STOPPED_RESULT_DELIVERY", "SIMULATED_VERIFIED_APPLIED", "SIMULATED_VERIFIED_NO_CHANGE", "SIMULATED_VERIFIED_DISK_TARGETS_ADOPTION_PENDING"].contains(value["status"] as? String ?? "")
        }
        let status = value["status"] as? String
        let exit = value["service_exit"] as? [String: Any]
        return (status == "FAILED_PARTIAL" || status == "VERIFIED_BACKUP_EXIT_UNCONFIRMED")
            && (DriverJobPolicy.strictTrue(exit?["resources_disposed"]) || DriverJobPolicy.strictFalse(value["camera_io"]))
    }

    func stop() {
        stopAudio()
        guard running else { return }
        if deviceJobRunning {
            message = "正在完成有界读取与退出；当前设备作业不能中途终止"
            return
        }
        stopped = true
        message = "正在停止…"
        guard let process, process.isRunning else { return }
        AppDiagnostics.terminate(process, reason: "user-cancelled")
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
            if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
        }
    }

    func stopNativePreview() {
        nativePreviewTask?.cancel()
        nativePreviewTask = nil
        nativePreviewRevision = UUID()
        nativePreviewReadyRevision = nil
        nativePreviewPending = false
        if let child = nativePreviewProcess, child.isRunning {
            AppDiagnostics.terminate(child, reason: "cancel-or-timeout")
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) }
            }
        }
        nativePreviewProcess = nil
    }

    func presentColdStartIfNeeded(_ value: [String: Any]?) {
        guard ColdStartInstructions.required(value) else { return }
        coldStartFinalAcceptance = ColdStartInstructions.finalAcceptance(value)
        coldStartForInstallation = value?["feature"] as? String == "selected-feature-install"
            && progress.estimate?.restoring == false
        coldStartForSTProtection = !coldStartForInstallation && ColdStartInstructions.consumerStage(value) == "ST_SAVED_PATCHES_RETAINED"
        coldStartInstallationVerified = coldStartForInstallation && DriverJobPolicy.verifiedWrite(value)
        if coldStartFinalAcceptance { finalColdStartReady = true; finalColdStartConfirmed = false }
        coldStartNotice = true
        message = coldStartForSTProtection ? ColdStartInstructions.stProtectionText + ColdStartInstructions.text :
            coldStartForInstallation ? "本次相机通信已退出；请按提示冷启动，再按安装结果检查所选功能。" + ColdStartInstructions.finalText :
            coldStartFinalAcceptance ? "机内读回与加载核验通过；请冷启动并验收功能。" : "本阶段已核验并退出通信，中间节点不是恢复完成。" + ColdStartInstructions.text
    }

    func startColdStartSteps() {
        guard coldStartNotice else { return }
        coldStartStepConfirmation.start()
        AppDiagnostics.shared.record("cold-start-steps-started", ["user_acknowledgement": true])
    }

    func confirmColdStartStepsCompleted() {
        guard coldStartNotice, coldStartStepConfirmation.complete() else { return }
        AppDiagnostics.shared.record("cold-start-steps-user-confirmed", [
            "user_reported_completed": true, "installation": coldStartForInstallation,
            "ST_protection": coldStartForSTProtection, "final_acceptance": coldStartFinalAcceptance,
            "native_boot_proof_replaced": false])
        if coldStartFinalAcceptance { finalColdStartConfirmed = true }
        else if !coldStartForInstallation { originalStartupConfirmed = true }
        if coldStartForInstallation,
           progress.finishInstallationCheck(verifiedWrite: coldStartInstallationVerified,
                userCompleted: coldStartStepConfirmation.completed, now: ProcessInfo.processInfo.systemUptime) {
            message = "本次安装已完成；你已确认按红字完成冷启动与功能检查。下一次修改前，请先从原始备份恢复。"
            AppDiagnostics.shared.record("installation-user-check-completed", progress.metadata)
        }
        coldStartNotice = false
    }

    func requestApplicationReview(_ feature: String) {
        if feature == "最终选择安装" { prepareSelectedInstall(); return }
        // This short-lived context is never saved with preferences or projects.
        if feature == "从备份恢复", let originalRestoreArchive, originalRestoreReceipt != nil {
            applicationReview = ApplicationReview(feature: feature, backupSummary: "已校验原始备份：\(originalRestoreArchive.lastPathComponent)。确认后先读取当前状态，再恢复已支持的功能区域。")
            return
        }
        let summary = backupVerified && selectedBackup != nil ?
            "本地已校验备份：\(selectedBackup!.lastPathComponent)。仍须重新确认本次备份。" :
            "当前尚未选择已校验的本次备份。必须先完成并校验备份。"
        applicationReview = ApplicationReview(feature: feature, backupSummary: summary)
    }

    func finishApplicationReview(_ id: UUID, backup: Bool, nonboot: Bool, ownRisk: Bool) {
        guard applicationReview?.id == id, backup, nonboot, ownRisk else { return }
        let feature = applicationReview!.feature
        applicationReview = nil
        if feature == "最终选择安装" {
            guard !running, dependencyOK, usbDependenciesOK, batteryConfirmed, mscConfirmed, connectionReady,
                  originalRestoreReceipt != nil, originalRestoreConfirmed, pendingSelectedConfig != nil else {
                error = "请确认本次原始备份、环境、电量、MSC与封存配置。"; return
            }
            makeDeviceBackup { self.executeSelectedInstall() }
            return
        }
        if feature == "从备份恢复" {
            guard originalRestorePhase != "STOP_UNKNOWN", originalRestorePhase != "STOPPED_RESULT_DELIVERY" else {
                error = "上一恢复结果未知，请先导出全部日志并检查；不会直接重试。"; return
            }
            guard !running, dependencyOK, usbDependenciesOK, batteryConfirmed, mscConfirmed, connectionReady,
                  originalRestoreReceipt != nil, originalRestoreConfirmed else {
                error = "请确认原始备份、环境、电量与 MSC，并完成只读连接检查。"; return
            }
            if originalRestoreLastJob != nil && !originalStartupConfirmed {
                error = "请按当前恢复节点冷启动、重新进入 MSC，并勾选确认。"; return
            }
            makeDeviceBackup(forRestore: true) { self.executeOriginalRestore(verifyAfterStartup: self.originalRestorePhase == "ALL_TARGETS_VERIFIED_REBOOT_PENDING" || self.originalRestorePhase == "ALL_TARGETS_READBACK_RO_PENDING" || self.originalRestorePhase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE") }
            return
        }
        guard !running, dependencyOK, usbDependenciesOK, batteryConfirmed, mscConfirmed,
              backupVerified, let captureReceipt else {
            error = "请先检查环境、电量与 MSC，并创建或导入含完整设置的便携备份。"; return
        }
        if feature == "最初备份恢复" { executeOriginalRestore(); return }
        if feature.hasPrefix("固定配置:") {
            prepareFixedFeature(String(feature.dropFirst("固定配置:".count))); return
        }
        if feature == "功能并集恢复" { restoreFixedFeature(); return }
        do {
            guard let job = try newJob(feature + "应用") else { return }
            var arguments: [String]
            if feature == "电子快门声开关" {
                arguments = ["driver", "sound-gate", "--state", (choices.desiredElectronicSoundEnabled ?? true) ? "enabled" : "disabled"]
            } else if feature == "滤镜" {
                guard !nativePreviewPending, nativePreviewError == nil,
                      nativePreviewReadyRevision == nativePreviewRevision else { throw CocoaError(.fileReadCorruptFile) }
                let config = job.appendingPathComponent("filters.json")
                try writeJSON(filterDriverConfiguration(), to: config)
                arguments = ["driver", "looks", "--config", config.path]
                if let nativeProject { arguments += ["--native-project", nativeProject.path] }
            } else if feature == "快门声音" {
                guard !kaShaPreparing, kaShaError == nil, let preview = kaShaPreview,
                      preview.revision == kaShaRevision else { throw CocoaError(.fileReadCorruptFile) }
                guard let gate = choices.lastGateCapsule else {
                    error = "请先应用电子快门声开关；原始备份会保留。此版声音安装仅支持原厂声音的首次安装。"; return
                }
                arguments = ["driver", "sound-scoped", "--prepared", preview.prepared.path, "--gate-capsule", gate]
            } else if feature == "本轮声音恢复" {
                guard let capsule = choices.lastSoundCapsule else { error = "尚无本轮声音恢复原件。"; return }
                arguments = ["driver", "sound-c-restore", "--capsule", capsule]
            } else if feature == "恢复备份" {
                guard let previousDeviceJob else {
                    error = "请选择本工具完成的应用作业收据；恢复会核对原备份与当前完整前像。"; return
                }
                arguments = ["driver", "restore", "--previous-job", previousDeviceJob.path]
            } else { throw CocoaError(.featureUnsupported) }
            if feature == "滤镜" || feature == "电子快门声开关", let path = choices.lastSoundJob {
                arguments += ["--sound-job", path]
            }
            if feature == "滤镜" || feature == "电子快门声开关" {
                for path in choices.completedProgramJobs ?? [] { arguments += ["--program-job", path] }
            }
            arguments += ["--capture", captureReceipt.path, "--output", job.appendingPathComponent("capture").path,
                "--compiler", resources.appendingPathComponent("zig/zig").path,
                "--execute", "--battery-confirmed", "--msc-confirmed", "--ack-backup", "--ack-brick", "--ack-risk"]
            run(arguments, title: "正在构建受限 helper、核对完整前像并应用，请等待…", job: job) { ok, result in
                if ok {
                    self.previousDeviceJob = job.appendingPathComponent("capture/job.private.json")
                    let receipt = self.previousDeviceJob!.path
                    if feature == "快门声音" { self.choices.lastSoundJob = receipt }
                    if feature == "电子快门声开关" { self.choices.lastGateCapsule = job.appendingPathComponent("capture/gate-C-capsule.private.json").path }
                    if feature == "快门声音" { self.choices.lastSoundCapsule = job.appendingPathComponent("capture/gate-sound-C-capsule.private.json").path }
                    if feature == "本轮声音恢复" { self.choices.lastSoundJob = nil }
                    if feature == "恢复备份", result?["feature"] as? String == "product-pin-inverse" {
                        self.choices.lastSoundJob = result?["restored_sound_job"] as? String
                    }
                    if feature == "恢复备份", let restored = result?["restore_of_job"] as? String,
                       let index = (self.choices.completedProgramJobs ?? []).firstIndex(of: restored) {
                        self.choices.completedProgramJobs = Array((self.choices.completedProgramJobs ?? []).prefix(index))
                    }
                    if feature == "滤镜" || feature == "电子快门声开关" {
                        self.choices.completedProgramJobs = (self.choices.completedProgramJobs ?? []) + [receipt]
                    }
                    if ["电子快门声开关", "快门声音", "本轮声音恢复"].contains(feature) {
                        self.captureSummary = "已验证的原始备份已保留；每次执行仍读取当前状态并校验本次改动与必要依赖。"
                    } else {
                        self.backupVerified = false
                        self.captureReceipt = nil
                        self.captureSummary = "应用已完整读回；下一次操作前请重新备份当前状态。"
                    }
                    self.message = DriverJobPolicy.strictTrue(result?["normal_power_cycle_required_before_resources"]) ?
                        "程序与设置已恢复并退出通信，图标／名称引用仍待处理；中间节点不是完成。" + ColdStartInstructions.text :
                        "写入、完整读回与普通 MSC 返回已核验；请普通关开机后检查声音／滤镜。"
                }
            }
        } catch { self.error = "本次应用尚未开始：\(error.localizedDescription)" }
    }

    var selectedSoundEnabled: Bool { choices.selectedSoundInstallMode != "none" }

    func fillSelectedPreset(_ preset: String) {
        selectedPreset = preset
        choices.includeFL2 = true; choices.includeFL3 = true
        if !choices.filters.isEmpty { choices.filters[0].enabled = preset == "1" }
        choices.selectedSoundInstallMode = preset == "3" ? "none" : "prepared"
        setSoundPreset(preset == "1" ? "m9-recock" : "m9")
        choices.recockEnabled = preset == "1"
        choices.recockGapMS = 40; choices.soundGainDB = 0
        choices.kaShaSwitchDenominator = 8
        choices.linkKaShaPairDelay = false; choices.kaShaPairDelayMS = 20
        selectedSnapshotSummary = ""
    }

    var selectedInstallResultUnknown: Bool {
        guard let path = choices.lastSelectedJob else { return false }
        guard let receipt = try? DriverJobPolicy.captureReceipt(at: URL(fileURLWithPath: path)),
              receipt["feature"] as? String == "selected-feature-install" else { return true }
        return ["STOP_UNKNOWN", "STOPPED_RESULT_DELIVERY"].contains(receipt["status"] as? String ?? "")
    }

    var selectedInstallReadiness: String {
        var missing: [String] = []
        if selectedInstallResultUnknown { missing.append("上一安装结果未知，请先导出诊断并检查，勿直接重试") }
        if !connectionReady { missing.append("完成只读连接检查") }
        if originalRestoreReceipt == nil || !originalRestoreConfirmed { missing.append("选择并确认修改前的原始完整备份") }
        if choices.filters.first?.enabled == true && (!choices.stNoticeAccepted || nativePreviewPending || nativePreviewError != nil || nativeProject == nil) {
            missing.append("确认 ST 基底须知并完成当前名称与图标预览")
        }
        if selectedSoundEnabled && (kaShaPreparing || kaShaPreview == nil || kaShaError != nil) { missing.append("完成最终声音生成与试听") }
        return missing.isEmpty ? "点击后先封存最终选择，再逐项确认风险；执行时还会检查原始基线。" : "还需要：" + missing.joined(separator: "；") + "。"
    }

    func prepareSelectedInstall() {
        guard !selectedInstallResultUnknown else { error = "上一安装结果未知，请先导出诊断并检查；不会直接重试。"; return }
        guard !running, let original = originalRestoreReceipt, originalRestoreConfirmed else {
            error = "请先选择并确认修改前的原始完整备份。"; return
        }
        do {
            guard let job = try newJob("最终选择安装") else { return }
            let m9 = choices.filters.first?.enabled == true
            var arguments = ["driver", "selected-freeze"]
            var draft: [String: Any] = ["schema": "a7m4-selected-draft/1",
                "filters": ["fl23": choices.includeFL2 && choices.includeFL3, "m9": m9]]
            if selectedSoundEnabled {
                let preview = try readyKaShaPreview()
                guard [8, 50].contains(choices.effectiveKaShaSwitchDenominator),
                      !choices.effectiveLinkKaShaPairDelay, abs(choices.effectiveKaShaPairDelayMS - 20) < 0.000001 else {
                    throw NSError(domain: "SelectedInstall", code: 1, userInfo: [NSLocalizedDescriptionKey: "机内分界仅支持1/8或1/50；固定 KASHA 内部间距为20 ms。请重新生成最终声音。"])
                }
                let pack = job.appendingPathComponent("prepared")
                try FileManager.default.copyItem(at: preview.prepared, to: pack)
                arguments += ["--prepared", pack.path]
                draft["sound"] = ["mode": "prepared", "gain_db": choices.effectiveSoundGainDB,
                    "recock_enabled": choices.effectiveRecockEnabled, "recock_gap_ms": choices.effectiveRecockGapMS,
                    "cutoff_seconds": choices.kaShaSwitchSeconds]
            } else { draft["sound"] = ["mode": "none"] }
            if m9 {
                guard choices.stNoticeAccepted, let item = choices.filters.first,
                      !nativePreviewPending, nativePreviewError == nil,
                      nativePreviewReadyRevision == nativePreviewRevision, let ready = nativeProject else {
                    throw NSError(domain: "SelectedInstall", code: 2, userInfo: [NSLocalizedDescriptionKey: "请确认 ST 基底须知并等待当前名称与六张原生图标预览完成。"])
                }
                let row = try nativeRow(item, slot: 1)
                let project = try SelectedDisplaySnapshot.freeze(project: ready, to: job.appendingPathComponent("icons"),
                    displayName: item.label, nativeRow: row, itemID: item.id)
                arguments += ["--native-project", project.path]
            }
            let input = job.appendingPathComponent("actual-ui-draft.json")
            try writeJSON(draft, to: input)
            let frozen = job.appendingPathComponent("selected-config.json")
            arguments += ["--draft", input.path, "--original-capture", original.path, "--output", frozen.path]
            let summary = "滤镜：" + (choices.includeFL2 && choices.includeFL3 ? "FL2／FL3 " : "") + (m9 ? "M9（\(choices.filters[0].label)）" : "无 M9")
                + "；声音：" + (selectedSoundEnabled ? "\(choices.soundPreset)，\(choices.effectiveSoundGainDB) dB，\(choices.effectiveRecockEnabled ? "有上弦" : "无上弦")，分界1/\(choices.effectiveKaShaSwitchDenominator)" : "无（静音）")
            run(arguments, title: "正在本地封存最终选择与素材…", job: job) { ok, value in
                guard ok, value?["schema"] as? String == "a7m4-selected-config/1",
                      let digest = value?["selection_sha256"] as? String, digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { return }
                self.pendingSelectedJob = job; self.pendingSelectedConfig = frozen; self.pendingSelectedSHA256 = digest
                self.selectedSnapshotSummary = summary
                self.applicationReview = ApplicationReview(feature: "最终选择安装", backupSummary:
                    "原始备份：\(self.originalRestoreArchive?.lastPathComponent ?? "已校验原始备份")。\n本次封存配置：\(summary)。\n每次需要修改前请先恢复到原始备份。")
            }
        } catch { self.error = "尚未开始安装：\(error.localizedDescription)" }
    }

    private func executeSelectedInstall() {
        guard let job = pendingSelectedJob, let frozen = pendingSelectedConfig, let confirmed = pendingSelectedSHA256,
              let capture = captureReceipt else { error = "本次封存配置或当前读取缺失，请重新准备。"; return }
        let output = job.appendingPathComponent("capture")
        let arguments = ["driver", "selected-install", "--capture", capture.path, "--selection", frozen.path, "--selection-sha256", confirmed,
            "--output", output.path, "--compiler", resources.appendingPathComponent("zig/zig").path,
            "--execute", "--battery-confirmed", "--msc-confirmed", "--ack-backup", "--ack-brick", "--ack-risk"]
        run(arguments, title: "正在检查原始基线并安装本次最终选择…", job: job) { ok, value in
            let receipt = output.appendingPathComponent("job.private.json")
            if FileManager.default.fileExists(atPath: receipt.path) { self.choices.lastSelectedJob = receipt.path }
            self.pendingSelectedJob = nil; self.pendingSelectedConfig = nil; self.pendingSelectedSHA256 = nil
            self.presentColdStartIfNeeded(value)
            self.coldStartInstallationVerified = ok && self.coldStartInstallationVerified
            if ok {
                self.originalRestoreLastJob = nil; self.originalRestorePhase = "ORIGINAL_IMPORTED"
                self.originalStartupConfirmed = false; self.saveRestoreProgress()
                self.message = "本次所选功能已写入并读回。请按提示冷启动后检查声音、滤镜名称图标、拍摄与回放。下一次修改前请先从原始备份恢复。"
            }
            self.saveChoices()
        }
    }

    func prepareFixedFeature(_ profile: String) {
        guard ["fl23", "custom1-m9", "all-current"].contains(profile) else { return }
        guard choices.lastFeatureCapsule == nil else { error = "请先完成本轮功能恢复，再开始下一套固定配置。"; return }
        // The finite enum selects recipes; Custom1 display comes from the
        // exact editor/preview snapshot frozen below, not a recipe label.
        func dispatch(_ icons: URL?, _ prepared: URL?) {
            do {
                guard let job = try self.newJob("固定配置-" + profile) else { return }
                var args = ["driver", "features", "--profile", profile]
                if let icons { args += ["--native-project", icons.path] }
                if let prepared { args += ["--prepared", prepared.path] }
                self.runFixedFeature(args, job: job, restoring: false)
            } catch { self.error = error.localizedDescription }
        }
        func sound(_ icons: URL?) {
            guard profile == "all-current" else { dispatch(icons, nil); return }
            do {
                guard let job = try self.newJob("固定配置-M9上弦准备") else { return }
                let input = job.appendingPathComponent("sound.json")
                try self.writeJSON(["schema": "a7m4-pin-sound-project/1", "preset": "m9-recock", "gain_db": 0,
                    "recock": ["enabled": true, "gap_ms": 40], "hybrid_cutoff": ["denominator": 50],
                    "kasha_synthesis": ["link_pair_delay_to_cutoff": true, "preserve_tails": true]], to: input)
                let prepared = job.appendingPathComponent("prepared")
                self.run(["pin-sound-prepare", input.path, "--output", prepared.path],
                         title: "正在本机准备 M9 上弦声音（40 ms）…", job: job) { ok, _ in
                    if ok { dispatch(icons, prepared) }
                }
            } catch { self.error = error.localizedDescription }
        }
        guard profile != "fl23" else { dispatch(nil, nil); return }
        do {
            guard let item = choices.filters.first, item.enabled,
                  !nativePreviewPending, nativePreviewError == nil,
                  nativePreviewReadyRevision == nativePreviewRevision, let ready = nativeProject else {
                throw NSError(domain: "NativeIcons", code: 21, userInfo: [NSLocalizedDescriptionKey:
                    "请启用第1槽，完成当前名称与图标编辑，并等待六张同版原生预览生成后再应用。"])
            }
            let row = try nativeRow(item, slot: 1)
            guard !item.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  item.label.unicodeScalars.count <= 32, item.label.utf8.count <= 63,
                  item.label.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw NSError(domain: "NativeIcons", code: 22, userInfo: [NSLocalizedDescriptionKey:
                    "显示名称须为1–32个可显示字符且UTF-8不超过63字节；不会截断或替换。"])
            }
            _ = try readNativeAssets(ready, itemIDs: [1: item.id])
            guard let job = try newJob("固定配置-显示快照") else { return }
            let project = job.appendingPathComponent("icons")
            try FileManager.default.copyItem(at: ready, to: project)
            let path = project.appendingPathComponent("manifest.json")
            guard var manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any],
                  let slots = manifest["slots"] as? [[String: Any]], slots.count == 1,
                  slots[0]["slot"] as? Int == 1, slots[0]["text"] as? String == row["text"] as? String else {
                throw CocoaError(.fileReadCorruptFile)
            }
            manifest["toolbox_display"] = ["schema": "a7m4-custom1-display/1", "slot": 1,
                "display_name": item.label, "icon_text": row["text"]!]
            manifest["output_dir"] = project.path
            let bytes = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
            try bytes.write(to: path, options: .atomic)
            _ = try readNativeAssets(project, itemIDs: [1: item.id])
            try writeJSON(["schema": "a7m4-editor-display-snapshot/1", "display_name": item.label,
                "native_row": row, "manifest_sha256": SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()],
                to: job.appendingPathComponent("display-snapshot.json"))
            sound(project)
        } catch { self.error = error.localizedDescription }
    }

    func restoreFixedFeature() {
        guard let capsule = choices.lastFeatureCapsule else { error = "尚无本轮功能修改的原件。"; return }
        guard choices.lastFeatureCheckpoint == nil || featureStartupConfirmed else {
            error = "请先按上次提示重启并回到 MSC，再继续恢复。"; return
        }
        do {
            guard let job = try newJob("功能并集恢复") else { return }
            var args = ["driver", "feature-c-restore", "--capsule", capsule]
            if let previous = choices.lastFeatureCheckpoint { args += ["--previous-job", previous] }
            runFixedFeature(args, job: job, restoring: true)
        } catch { self.error = error.localizedDescription }
    }

    private func clearVerifiedEmptyFeatureReference() {
        guard choices.lastFeatureCheckpoint == nil, let path = choices.lastFeatureCapsule,
              DriverJobPolicy.verifiedEmptyFeatureAttempt(at: URL(fileURLWithPath: path)) else { return }
        choices.lastFeatureCapsule = nil
        saveChoices() // Only the preference reference changes; evidence stays.
    }

    private func runFixedFeature(_ inputs: [String], job: URL, restoring: Bool) {
        guard backupVerified, let captureReceipt else { error = "请先选择并校验原始备份。"; return }
        guard restoring || choices.lastFeatureCapsule == nil else { error = "上一轮原件仍需保留，请先完成恢复。"; return }
        let capture = job.appendingPathComponent("capture")
        let arguments = inputs + ["--capture", captureReceipt.path, "--output", capture.path,
            "--compiler", resources.appendingPathComponent("zig/zig").path,
            "--execute", "--battery-confirmed", "--msc-confirmed", "--ack-backup", "--ack-brick", "--ack-risk"]
        run(arguments, title: "正在核对 C／D、应用差异并读回，请等待…", job: job) { ok, value in
            // Keep a real partial capsule accessible after a failed job. A
            // subsequent plan still verifies its hash, body and actual C.
            let capsule = capture.appendingPathComponent("feature-union-C-capsule.private.json")
            if !restoring && FileManager.default.fileExists(atPath: capsule.path)
                && !DriverJobPolicy.verifiedEmptyFeatureAttempt(at: capsule) {
                self.choices.lastFeatureCapsule = capsule.path
            }
            guard ok else { self.saveChoices(); return }
            self.previousDeviceJob = capture.appendingPathComponent("job.private.json")
            if DriverJobPolicy.verifiedFeatureCheckpoint(value) {
                self.choices.lastFeatureCapsule = capsule.path
                self.choices.lastFeatureCheckpoint = self.previousDeviceJob!.path
                self.featureStartupConfirmed = false
                self.choices.featureProgressFraction = self.progress.fraction
                self.choices.featureProgressProfile = value?["profile"] as? String
                self.choices.featureMachineSeconds = self.progress.priorActiveSeconds + self.progress.activeSeconds
                self.choices.featureUserWaitSeconds = self.progress.priorWaitSeconds + self.progress.userWaitSeconds
                self.choices.featureWaitStartedAt = Date()
                self.choices.featureCheckpointCount = (self.choices.featureCheckpointCount ?? 0) + 1
                self.presentColdStartIfNeeded(value)
                self.message = self.choices.featureCheckpointCount == 1 ?
                    "程序／设置已恢复并读回，通信已退出，资源引用与尾部尚待处理；中间节点不是完成。" + ColdStartInstructions.text :
                    "已到新的已验证冷启动节点，通信已退出；中间节点不是完成。" + ColdStartInstructions.text
            } else {
                self.choices.lastFeatureCheckpoint = nil
                if restoring { self.choices.lastFeatureCapsule = nil }
                self.choices.featureProgressFraction = nil
                self.choices.featureWaitStartedAt = nil
                self.choices.featureCheckpointCount = nil
                self.choices.featureMachineSeconds = nil
                self.choices.featureUserWaitSeconds = nil
                self.featureStartupConfirmed = false
                self.message = restoring ? "本轮实际 C 已恢复并读回。请冷启动，检查名称图标、声音、拍照、回放和普通关开机。" :
                    "安装与读回完成。请按提示冷启动并检查所选功能，再回 MSC 恢复本轮实际 C。"
            }
            self.captureSummary = "原始备份已保留；后续读取当前状态，仅 C／必要 D 阻断，E／F 记录变化。"
            self.saveChoices()
        }
    }

    func checkDependencies() {
        guard !running else { return }
        driverBackupCoordinationReady = false
        run(["driver", "doctor"], title: "正在检查应用运行环境…") { ok, result in
            self.dependencyChecked = true
            self.dependencyOK = ok && (result?["ready_for_local_work"] as? Bool == true)
            let pmca = result?["pmca_sources"] as? [String: Any]
            self.usbDependenciesOK = ok && DriverJobPolicy.strictTrue(result?["ready_for_explicit_usb_session"])
                && DriverJobPolicy.strictTrue(pmca?["ready"])
            if result?["status"] as? String == "LOCAL_DEPENDENCIES_NOT_READY" {
                self.message = "Mac 本地依赖未就绪；没有检测或连接相机"
                self.error = result?["error"] as? String ?? "Mac 本地依赖无法加载，请查看诊断日志。"
                return
            }
            self.run(["driver", "status"], title: "正在核对本地 driver 就绪状态…") { statusOK, status in
                self.driverBackupCoordinationReady = statusOK && DriverJobPolicy.backupCoordinatorReady(status)
                self.message = self.backupReadinessNote
            }
        }
    }

    // Presentation-only continuous QA. Offline mode denies every USB observer
    // and device process in run(); these values never become native receipts.
    func advanceOfflineSequence() {
        guard ProductIdentity.offlineQA else { return }
        let scenario = ProductIdentity.qaScenario, now = ProcessInfo.processInfo.systemUptime
        if scenario == "sequence-install" {
            if offlineSequenceStep == 0 {
                progress.begin(OperationEstimate.select(["driver", "selected-install"], profile: ""), now: now, wait: false)
                progress.tick(now: now + 430)
                progress.finish(accepted: true, verifiedComplete: true, checkpoint: true, now: now + 430)
                coldStartForInstallation = true; coldStartInstallationVerified = true
                coldStartStepConfirmation.reset(); coldStartNotice = true; running = false
                message = "离线样例：机器写入读回结束；等待两步冷启动确认。"
            } else { message = "请完成冷启动窗口中的两步确认；离线样例未产生设备收据。" }
        } else if scenario == "sequence-restore" {
            switch offlineSequenceStep {
            case 0:
                progress.begin(OperationEstimate.select(["driver", "backup-target-restore"], profile: ""), now: now, wait: false)
                progress.finish(accepted: true, verifiedComplete: false, checkpoint: true, now: now + 145)
                originalConsumerSafetyStage = "ST_SAVED_PATCHES_RETAINED"; progress.consumerSafetyStage = originalConsumerSafetyStage
                originalRestorePhase = "RUNTIME_BOUNDARY_REQUIRED"; running = false
                coldStartForSTProtection = true; coldStartForInstallation = false; coldStartFinalAcceptance = false
                coldStartStepConfirmation.reset(); coldStartNotice = true
                message = ColdStartInstructions.stProtectionText + "（离线样例）"
            case 1:
                guard coldStartStepConfirmation.completed else { message = "离线样例：请先完成 ST 节点红字冷启动的两步确认。"; return }
                let active = progress.activeSeconds + progress.priorActiveSeconds, saved = progress.fraction
                progress.begin(OperationEstimate.select(["driver", "backup-target-restore", "--previous-job", "offline"], profile: ""), now: now, wait: false,
                    saved: saved, priorActive: active, priorWait: 300)
                progress.phase = "RESOURCE_FINISH"; running = true
                originalConsumerSafetyStage = ""; message = "离线样例：续接资源恢复，累计机器时间保留。"
            case 2:
                progress.finish(accepted: true, verifiedComplete: false, checkpoint: true, now: now + 694)
                originalRestorePhase = "ALL_TARGETS_VERIFIED_REBOOT_PENDING"; running = false
                coldStartForSTProtection = false; coldStartForInstallation = false; coldStartFinalAcceptance = false
                coldStartStepConfirmation.reset(); coldStartNotice = true
                message = "离线样例：资源已读回，等待冷启动；尚未完成恢复。"
            case 3:
                guard coldStartStepConfirmation.completed else { message = "离线样例：请先完成资源节点红字冷启动的两步确认。"; return }
                let active = progress.activeSeconds + progress.priorActiveSeconds, saved = progress.fraction
                progress.begin(OperationEstimate.select(["driver", "backup-target-verify", "--previous-job", "offline"], profile: ""), now: now, wait: false,
                    saved: saved, priorActive: active, priorWait: 600)
                progress.finish(accepted: true, verifiedComplete: false, checkpoint: true, now: now + 70)
                progress.phase = "WAITING_FUNCTION_CHECK"
                originalRestorePhase = "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE"
                finalColdStartReady = true; finalColdStartConfirmed = false; running = false
                coldStartForSTProtection = false; coldStartForInstallation = false; coldStartFinalAcceptance = true
                coldStartStepConfirmation.reset(); coldStartNotice = true
                message = "离线样例：启动后只读核验完成；等待冷启动及四项功能观察。"
            default:
                guard coldStartStepConfirmation.completed, finalColdStartConfirmed, originalNamesAccepted, originalSoundAccepted, originalShootAccepted, originalPlaybackAccepted else {
                    message = "离线样例：请先勾选冷启动及四项功能观察。"; return
                }
                progress.finish(accepted: true, verifiedComplete: true, checkpoint: false, now: now)
                originalRestorePhase = "USER_ACCEPTED_BACKUP_SCOPE_RESTORATION"
                message = "离线样例：恢复验收已完成。没有设备操作或设备收据。"
            }
        } else if scenario == "sequence-failure" {
            progress.begin(OperationEstimate.select(["driver", "selected-install"], profile: ""), now: now, wait: false)
            progress.finish(accepted: false, verifiedComplete: false, checkpoint: false, now: now + 40)
            running = false; coldStartInstallationVerified = false
            message = "离线失败样例：核验未通过，进度不显示完成。"
        } else { return }
        offlineSequenceStep += 1
    }

    func applyOfflineVisualFixture() {
        guard ProductIdentity.offlineQA else { return }
        message = "离线界面演示：未连接相机，设备操作已禁用。"
        if ProcessInfo.processInfo.environment["A7M4_QA_APPEARANCE"] == "dark" { NSApp.appearance = NSAppearance(named: .darkAqua) }
        else { NSApp.appearance = NSAppearance(named: .aqua) }
        let scenario = ProductIdentity.qaScenario
        if let first = choices.filters.first, let path = ProcessInfo.processInfo.environment["A7M4_QA_ICONS"],
           let urls = try? readNativeAssets(URL(fileURLWithPath: path), itemIDs: [1: first.id]) {
            choices.filters[0].label = "Film 9"; choices.filters[0].iconText = "Po"; choices.stNoticeAccepted = true
            nativeIconURLs = urls; nativeProject = URL(fileURLWithPath: path)
            nativePreviewPending = false; nativePreviewReadyRevision = nativePreviewRevision
        }
        if scenario.hasPrefix("sequence-") {
            progress.begin(OperationEstimate.select(["driver", scenario == "sequence-restore" ? "backup-target-restore" : "selected-install"], profile: ""),
                now: ProcessInfo.processInfo.systemUptime, wait: false)
            message = "离线连续场景：使用顶部样例按钮推进；设备操作保持禁用。"
        }
        if scenario == "low-space" { outputSpaceWarning = "离线磁盘不足样例：本次数据估计需 512 MiB，另建议预留 1 GiB 日志空间。此提示不阻止继续。" }
        if scenario == "backup-import" {
            backupImportRunning = true
            backupImportSummary = "校验核心备份 · 已用 12 秒（离线阶段样例）"
            running = true
        }
        if ["restore-target", "cold-start"].contains(scenario) {
            originalRestoreArchive = ProductIdentity.qaRoot.appendingPathComponent("original.a7capture")
            originalRestoreReceipt = ProductIdentity.qaRoot.appendingPathComponent("sample-capture.private.json")
            originalRestorePhase = "ORIGINAL_IMPORTED"
        }
        if ["final-acceptance", "final-acceptance-page"].contains(scenario) {
            originalRestorePhase = "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE"
            finalColdStartReady = true; finalColdStartConfirmed = false
            coldStartFinalAcceptance = true
            coldStartNotice = scenario == "final-acceptance"
        }
        if scenario == "cold-start" {
            originalRestoreLastJob = ProductIdentity.qaRoot.appendingPathComponent("sample-job.private.json")
            originalRestorePhase = "RUNTIME_BOUNDARY_REQUIRED"
            coldStartNotice = true
        }
        if ["install-cold-start", "install-cold-start-preflight"].contains(scenario) {
            coldStartForInstallation = true; coldStartNotice = true
            coldStartInstallationVerified = scenario == "install-cold-start"
            let now = ProcessInfo.processInfo.systemUptime
            progress.begin(OperationEstimate.select(["driver", "selected-install"], profile: ""), now: now, wait: false)
            progress.activeSeconds = 430; progress.fraction = 0.51
            progress.paused = true; progress.phase = "WAITING_RESTART"
        }
        if ["st-protection", "st-protection-page"].contains(scenario) {
            originalRestorePhase = "RUNTIME_BOUNDARY_REQUIRED"
            originalConsumerSafetyStage = "ST_SAVED_PATCHES_RETAINED"
            coldStartForSTProtection = true; coldStartNotice = scenario == "st-protection"
            progress.begin(OperationEstimate.select(["driver", "backup-target-restore"], profile: ""),
                now: ProcessInfo.processInfo.systemUptime, wait: false)
            progress.finish(accepted: true, verifiedComplete: false, checkpoint: true, now: ProcessInfo.processInfo.systemUptime)
            progress.consumerSafetyStage = originalConsumerSafetyStage
            message = ColdStartInstructions.stProtectionText
        }
        if ["restore-wait", "restore-run", "complete"].contains(scenario) {
            timingProfile = "custom1-m9"
            progress.begin(OperationEstimate.select(["driver", "feature-c-restore", "--previous-job", "offline"], profile: timingProfile),
                now: ProcessInfo.processInfo.systemUptime, wait: scenario == "restore-wait", saved: 2.0/18)
            if scenario == "restore-wait" {
                choices.lastFeatureCheckpoint = "OFFLINE_FIXTURE"; choices.featureCheckpointCount = 1
                progress.phase = "WAITING_RESTART"
            } else if scenario == "restore-run" { running = true; deviceJobRunning = true; progress.fraction = 0.43; progress.phase = "RESOURCE_FINISH" }
            else { progress.complete = true; progress.fraction = 1; progress.phase = "VERIFIED_COMPLETE" }
        }
        if scenario == "overdue" {
            progress.begin(OperationEstimate.select(["driver", "features"], profile: "all-current"), now: 0, wait: false)
            progress.activeSeconds = 1000; progress.fraction = 0.95; running = true; deviceJobRunning = true
        }
        if scenario == "identity-error" { error = "未匹配支持的6.02构建；已停止，不可通过用户确认绕过。（离线提示样例）" }
        if scenario == "backup-data" {
            backupDataVerified = true; backupVerified = false; captureReceipt = nil; dataCaptureReceipt = nil
            captureSummary = "11 个对象及完整设置已核验，可立即本地保存；当前 MSC 返回仍未确认，应用入口保持禁用。（离线样例）"
        }
    }

    func checkConnection() {
        guard !running else { return }
        connectionReady = false
        run(["driver", "connection-check"], title: "正在只读检查 Mac 的相机连接…") { ok, result in
            self.connectionReady = ok && result?["schema"] as? String == "a7m4-host-connection-check/1"
                && DriverJobPolicy.strictTrue(result?["connected"]) && DriverJobPolicy.strictFalse(result?["camera_io"])
            self.connectionSummary = self.connectionReady ? "已观察到 ILCE-7M4 · MSC；固件仍须在实际读取时核验" : "连接尚未就绪，请按提示完成系统允许与 MSC 设置"
            self.message = self.connectionSummary
        }
    }

    func inspectLocalCapture(_ receipt: URL) {
        guard !running else { return }
        backupVerified = false; backupDataVerified = false; captureReceipt = nil; dataCaptureReceipt = nil; selectedBackup = nil
        run(["driver", "capture-inspect", "--capture", receipt.path], title: "正在本地核验已有完整备份数据…") { ok, result in
            guard ok, result?["schema"] as? String == "a7m4-capture-data/1",
                  DriverJobPolicy.strictTrue(result?["data_integrity_verified"]), result?["receipt"] as? String == receipt.path,
                  DriverJobPolicy.strictTrue(result?["normal_return_verified"]) || DriverJobPolicy.strictFalse(result?["normal_return_verified"]) else { return }
            self.backupDataVerified = true; self.dataCaptureReceipt = receipt
            if let archive = result?["archive"] as? String { self.selectedBackup = URL(fileURLWithPath: archive) }
            if DriverJobPolicy.strictTrue(result?["normal_return_verified"]) {
                self.backupVerified = true; self.captureReceipt = receipt
                self.captureSummary = "完整备份数据已本地核验；后续执行仍检查当前机身与新鲜依赖。"
            } else {
                self.captureSummary = "完整备份对象及设置已核验，可立即本地保存；当前 MSC 返回仍未确认，应用入口保持禁用。"
            }
            self.message = self.captureSummary
        }
    }

    func chooseCaptureFolder() {
        guard let selected = folder("选择包含 capture.private.json 的完整 capture 文件夹") else { return }
        inspectLocalCapture(selected.appendingPathComponent("capture.private.json"))
    }

    func exportCaptureData() {
        guard backupDataVerified, let receipt = dataCaptureReceipt, !running else { return }
        let panel = NSSavePanel(); panel.title = "保存完整便携备份"; panel.nameFieldStringValue = "A7IV-original"
        panel.allowedContentTypes = [UTType(filenameExtension: "a7capture") ?? .data]
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        guard !FileManager.default.fileExists(atPath: destination.path) else { error = "请选择新的文件名；不会覆盖已有备份。"; return }
        run(["driver", "capture-export", "--capture", receipt.path, "--output", destination.path], title: "正在本地保存完整备份，不重新读取相机…") { ok, result in
            guard ok, DriverJobPolicy.strictTrue(result?["data_integrity_verified"]) else { return }
            self.selectedBackup = destination
            let source = try? DriverJobPolicy.captureReceipt(at: receipt)
            self.message = DriverJobPolicy.strictTrue(source?["normal_return_verified"]) ? "完整备份已保存并核验。" : "完整数据已保存；原 MSC 未确认状态与失败历史保持不变。"
        }
    }

    func confirmMSCAndContinue() {
        guard backupDataVerified, let receipt = dataCaptureReceipt, !running else { return }
        do {
            guard let job = try newJob("MSC只读收尾") else { return }
            let adopted = job.appendingPathComponent("adopted", isDirectory: true)
            run(["driver", "capture-adopt", "--capture", receipt.path, "--output", adopted.path], title: "正在只读等待 MSC／系统允许，最多 60 秒…", job: job) { ok, result in
                guard ok, result?["schema"] as? String == "a7m4-capture-adopt/1", DriverJobPolicy.strictTrue(result?["normal_return_verified"]),
                      result?["receipt"] as? String == adopted.appendingPathComponent("capture.private.json").path else { return }
                do {
                    let target = adopted.appendingPathComponent("capture.private.json")
                    let saved = try DriverJobPolicy.captureReceipt(at: target)
                    _ = try DriverJobPolicy.validatedBackup(saved, captureRoot: adopted)
                    self.captureReceipt = target; self.dataCaptureReceipt = target
                    self.backupVerified = true; self.backupDataVerified = true; self.connectionReady = true
                    self.selectedBackup = adopted.appendingPathComponent("original.a7backup")
                    self.localSnapshot = adopted.appendingPathComponent("snapshot", isDirectory: true)
                    self.captureSummary = "当前 MSC 已由新的只读证据确认，数据已接纳到新目录；原失败收据未改写。"
                    self.message = self.captureSummary
                } catch { self.error = error.localizedDescription }
            }
        } catch { self.error = error.localizedDescription }
    }

    func makeDeviceBackup(forRestore: Bool = false, completion: (() -> Void)? = nil) {
        guard canCaptureDeviceBackup else { error = backupReadinessNote; return }
        do {
            guard let job = try newJob("机身只读备份") else { return }
            let capture = job.appendingPathComponent("capture", isDirectory: true)
            backupVerified = false; backupDataVerified = false; dataCaptureReceipt = nil; connectionReady = false
            selectedBackup = nil
            readingCurrentForRestore = forRestore
            run(["driver", "backup", "--output", capture.path, "--execute", "--battery-confirmed", "--msc-confirmed"],
                title: "正在完成 11 对象的有界读取与退出，请等待…", job: job) { ok, result in
                if self.readingCurrentForRestore {
                    self.restoreMachineSeconds = self.progress.priorActiveSeconds + self.progress.activeSeconds
                    self.restoreWaitSeconds = self.progress.priorWaitSeconds + self.progress.userWaitSeconds
                    self.restoreProgressFraction = min(0.95,self.progress.fraction)
                    self.saveRestoreProgress()
                }
                self.readingCurrentForRestore = false
                if result?["status"] as? String == "AUTH_DEPENDENCIES_NOT_READY" {
                    self.captureSummary = "管理员后台依赖未就绪，未发送相机协议请求；没有新备份。"
                    return
                }
                if result?["status"] as? String == "AUTH_CANCELLED" {
                    self.captureSummary = "本次系统授权已取消，未启动读取；没有新备份。"
                    return
                }
                let receipt = capture.appendingPathComponent("capture.private.json")
                let saved = try? DriverJobPolicy.captureReceipt(at: receipt)
                if DriverJobPolicy.strictTrue(saved?["camera_io"]), let version = saved?["firmware_version"] as? String,
                   let model = saved?["model"] as? String {
                    self.cameraObservation = "最近一次读取记录：\(model) · \(version)"
                }
                let count = saved?["stable_object_count"] as? Int ?? 0
                self.captureSummary = "最近一次读取：\(count)／\(saved?["expected_object_count"] as? Int ?? 11) 对象通过双读；\(saved?["status"] as? String ?? "收据未知")"
                if saved?["status"] as? String == "VERIFIED_BACKUP_EXIT_UNCONFIRMED", DriverJobPolicy.verifiedBackupData(saved) {
                    self.inspectLocalCapture(receipt)
                    return
                }
                guard ok, DriverJobPolicy.verifiedBackup(result) else { return }
                do {
                    let accepted = try DriverJobPolicy.validatedBackup(result, captureRoot: capture)
                    let archive = URL(fileURLWithPath: accepted["archive"] as! String)
                    let snapshot = URL(fileURLWithPath: accepted["snapshot_dir"] as! String, isDirectory: true)
                    self.selectedBackup = archive
                    self.localSnapshot = snapshot
                    self.captureReceipt = receipt
                    self.backupVerified = true; self.backupDataVerified = true; self.dataCaptureReceipt = receipt; self.connectionReady = true
                    self.captureSummary = "11 个文件双读一致；前后两份完整设置原件已保存并核对结构。执行前将按所选功能再次校验设置。"
                    if let portable = accepted["portable_archive"] as? [String: Any], let path = portable["path"] as? String {
                        self.selectedBackup = URL(fileURLWithPath: path)
                    }
                    self.message = "本次 11 对象备份已核验；可查看本机原件和收据"
                    completion?()
                } catch {
                    self.backupVerified = false
                    self.captureSummary = "本次备份收据未通过核对"
                    self.message = "本次备份尚未确认完整，请查看报告"
                    self.error = error.localizedDescription
                }
            }
        } catch { self.error = error.localizedDescription }
    }

    func chooseSnapshot() {
        guard let folder = folder("选择已有机身快照文件夹") else { return }
        localSnapshot = folder
        message = "已选择本地快照，创建备份时会核对必需对象"
    }

    func makeBackup() {
        guard let snapshot = localSnapshot else { return }
        captureReceipt = nil
        backupVerified = false
        do {
            guard let job = try newJob("机身备份") else { return }
            run(["backup-create", snapshot.path, "--output", job.appendingPathComponent("camera.a7backup").path],
                title: "正在核对快照并创建可恢复备份…", job: job) { ok, result in
                let archive = job.appendingPathComponent("camera.a7backup")
                self.backupVerified = ok && result?["verified"] as? Bool == true &&
                    result?["complete"] as? Bool == true && FileManager.default.fileExists(atPath: archive.path)
                if self.backupVerified { self.selectedBackup = archive }
            }
        } catch { self.error = error.localizedDescription }
    }

    func chooseAndVerifyBackup() {
        guard !running else { return }
        guard let archive = file("选择完整 .a7capture 或旧 .a7backup 备份文件") else { return }
        selectedBackup = archive
        backupVerified = false; backupDataVerified = false; dataCaptureReceipt = nil
        captureReceipt = nil
        do {
            guard let job = try newJob("备份校验") else { return }
            if archive.pathExtension.lowercased() == "a7capture" {
                backupImportRunning = true; backupImportFailed = false
                backupImportSummary = "正在打开并校验所选备份；校验期间请保留此窗口。"
                captureSummary = "正在校验：" + archive.lastPathComponent
                run(["driver", "portable-import", archive.path, "--output", job.appendingPathComponent("imported").path],
                    title: "正在校验并导入完整便携备份…", job: job) { ok, result in
                    defer {
                        self.backupImportRunning = false
                        if !self.backupDataVerified {
                            self.backupImportFailed = true
                            self.backupImportSummary = "备份校验未通过：" + (self.error ?? "结果缺少完整性证明，请查看诊断报告。")
                            self.captureSummary = "所选备份未获确认；保存及应用入口未开放。"
                        } else {
                            self.backupImportSummary = self.captureSummary
                        }
                    }
                    guard ok, DriverJobPolicy.strictTrue(result?["verified"]), DriverJobPolicy.strictTrue(result?["complete"]),
                          let receipt = result?["receipt"] as? String, let snapshot = result?["snapshot_dir"] as? String else { return }
                    guard DriverJobPolicy.strictTrue(result?["normal_return_verified"]) || DriverJobPolicy.strictFalse(result?["normal_return_verified"]) else {
                        self.error = "导入结果缺少明确的正常返回状态；未开放应用入口。"
                        return
                    }
                    self.dataCaptureReceipt = URL(fileURLWithPath: receipt); self.backupDataVerified = true
                    self.localSnapshot = URL(fileURLWithPath: snapshot)
                    if DriverJobPolicy.strictFalse(result?["normal_return_verified"]) {
                        self.captureReceipt = nil; self.backupVerified = false
                        self.captureSummary = "完整数据已导入，可本地保存；原 MSC 未确认状态保留，应用入口仍禁用。"
                        self.message = self.captureSummary
                        return
                    }
                    self.captureReceipt = URL(fileURLWithPath: receipt)
                    self.backupVerified = true
                    self.captureSummary = "完整原始备份已导入并校验；执行前重新读取本次 C／必要 D，E／F 仅记录变化。"
                    self.message = "完整便携备份已校验；执行前仍会核对同一机身、本次改动前像与必要依赖。"
                }
                return
            }
            run(["backup-verify", archive.path, "--output", job.appendingPathComponent("verification.json").path],
                title: "正在校验备份完整性与恢复范围…", job: job) { ok, result in
                self.backupVerified = ok && result?["verified"] as? Bool == true &&
                    result?["complete"] as? Bool == true && FileManager.default.fileExists(atPath: archive.path)
            }
        } catch {
            self.error = error.localizedDescription
            backupImportRunning = false; backupImportFailed = true
            backupImportSummary = "备份校验未能开始：" + error.localizedDescription
        }
    }

    func chooseCompletedDeviceJob() {
        guard let receipt = file("选择本工具已完成应用的 job.private.json") else { return }
        previousDeviceJob = receipt
    }

    func chooseOriginalRestoreBackup() {
        guard let archive = file("选择任何修改之前保存的最初完整 .a7capture 备份") else { return }
        guard archive.pathExtension.lowercased() == "a7capture" else {
            error = "恢复需要包含设置与固件证据的完整 .a7capture；旧 .a7backup 不能替代。"; return
        }
        originalRestoreReceipt = nil
        originalRestoreArchive = nil
        originalRestoreConfirmed = false
        do {
            guard let job = try newJob("最初备份导入") else { return }
            let output = job.appendingPathComponent("original")
            backupImportRunning = true; backupImportFailed = false
            backupImportSummary = "正在校验所选原始备份…"
            run(["driver", "portable-import", archive.path, "--output", output.path],
                title: "正在校验最初完整备份…", job: job) { ok, result in
                defer {
                    self.backupImportRunning = false
                    self.backupImportFailed = self.originalRestoreReceipt == nil
                    self.backupImportSummary = self.originalRestoreReceipt == nil ? "原始备份校验未通过：" + (self.error ?? "请查看诊断报告。") : "原始备份数据已校验；历史 MSC 状态不会替代当前机身检查。"
                }
                guard ok, result?["schema"] as? String == "a7m4-portable-import/1",
                      DriverJobPolicy.strictTrue(result?["verified"]), DriverJobPolicy.strictTrue(result?["complete"]),
                      result?["receipt"] as? String == output.appendingPathComponent("capture.private.json").path else { return }
                self.originalRestoreReceipt = output.appendingPathComponent("capture.private.json")
                self.originalRestoreArchive = archive
                self.originalRestoreLastJob = nil
                self.originalRestoreFailureJob = nil
                self.originalRestorePhase = "ORIGINAL_IMPORTED"
                self.restoreProgressFraction = 0; self.restoreMachineSeconds = 0; self.restoreWaitSeconds = 0
                self.restoreWaitStartedAt = nil
                self.saveRestoreProgress()
                self.message = "原始备份数据已校验。确认后会自动读取当前状态，再恢复已支持的功能区域。"
            }
        } catch { self.error = error.localizedDescription }
    }

    func restorePlan() {
        guard let captureReceipt, let originalRestoreReceipt, originalRestoreConfirmed else {
            error = "请导入并确认最初完整备份，同时准备当前完整备份。"; return
        }
        do {
            guard let job = try newJob("最初备份差异核对") else { return }
            run(["driver", "backup-target-plan", "--capture", captureReceipt.path,
                 "--original-capture", originalRestoreReceipt.path,
                 "--output", job.appendingPathComponent("original-restore-plan.json").path],
                title: "正在对比当前完整文件、设置与最初备份，生成条件恢复计划…", job: job)
        } catch { self.error = error.localizedDescription }
    }

    private func executeOriginalRestore(verifyAfterStartup: Bool = false) {
        guard let captureReceipt, let originalRestoreReceipt, originalRestoreConfirmed, backupVerified else {
            error = "请确认最初备份，并创建当前完整备份。"; return
        }
        do {
            guard let job = try newJob(verifyAfterStartup ? "启动后原始恢复核验" : "最初备份恢复") else { return }
            var arguments = ["driver", verifyAfterStartup ? "backup-target-verify" : "backup-target-restore",
                "--capture", captureReceipt.path, "--original-capture", originalRestoreReceipt.path,
                "--output", job.appendingPathComponent("capture").path,
                "--compiler", resources.appendingPathComponent("zig/zig").path,
                "--execute", "--battery-confirmed", "--msc-confirmed", "--ack-original"]
            if let originalRestoreLastJob { arguments += ["--previous-job", originalRestoreLastJob.path] }
            if verifyAfterStartup || originalRestoreLastJob != nil { arguments += ["--startup-confirmed"] }
            arguments += ["--ack-backup", "--ack-brick", "--ack-risk"]
            run(arguments, title: verifyAfterStartup ? "正在只读核验完整原件与当前加载…" : "正在恢复原始差异并完整读回…", job: job) { ok, result in
                guard ok, DriverJobPolicy.verifiedBackupTargetCheckpoint(result) else {
                    self.finalColdStartReady = false; self.finalColdStartConfirmed = false
                    self.backupVerified = false; self.captureReceipt = nil
                    self.originalRestoreFailureJob = job.appendingPathComponent("capture/job.private.json")
                    self.originalRestorePhase = result?["status"] as? String ?? "REVIEW_REQUIRED"
                    self.originalConsumerSafetyStage = ""
                    self.saveRestoreProgress()
                    if self.originalRestorePhase == "STOP_UNKNOWN" {
                        self.message = "本次结果未知，请停止操作并导出诊断日志供排查；应用不会自动重试或重启相机。"
                    }
                    return
                }
                self.originalRestoreLastJob = job.appendingPathComponent("capture/job.private.json")
                self.originalRestorePhase = result?["status"] as? String ?? "UNKNOWN"
                self.originalConsumerSafetyStage = ColdStartInstructions.consumerStage(result)
                self.progress.consumerSafetyStage = self.originalConsumerSafetyStage
                AppDiagnostics.shared.record("restore-consumer-safety", ["stage": self.originalConsumerSafetyStage, "phase": self.originalRestorePhase])
                self.finalColdStartReady = ColdStartInstructions.finalAcceptance(result)
                self.finalColdStartConfirmed = false
                if self.originalRestorePhase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" {
                    self.progress.paused = true; self.progress.phase = "WAITING_FUNCTION_CHECK"
                }
                self.restoreProgressFraction = min(0.95,self.progress.fraction)
                self.restoreMachineSeconds = self.progress.priorActiveSeconds + self.progress.activeSeconds
                self.restoreWaitSeconds = self.progress.priorWaitSeconds + self.progress.userWaitSeconds
                self.restoreWaitStartedAt = Date()
                self.originalStartupConfirmed = false
                self.originalColdStartRequired = DriverJobPolicy.strictTrue((result?["finalizer"] as? [String: Any])?["requires_physical_cold_start"])
                self.originalNamesAccepted = false; self.originalSoundAccepted = false
                self.originalShootAccepted = false; self.originalPlaybackAccepted = false
                self.backupVerified = false; self.captureReceipt = nil
                self.saveRestoreProgress()
                if self.originalRestorePhase == "RUNTIME_BOUNDARY_REQUIRED" {
                    self.message = self.originalConsumerSafetyStage == "ST_SAVED_PATCHES_RETAINED" ? ColdStartInstructions.stProtectionText :
                        "本轮已安全退出，进度已保存。程序恢复后的资源收尾仍需继续；请查看报告中的边界原因。" + (result?["error"] as? String ?? "")
                } else if verifyAfterStartup {
                    self.message = "机内读回与加载核验通过；请冷启动并验收功能。"
                } else {
                    self.message = "本轮功能区域已读回。请按提示正常关开机，再运行启动后核验。"
                }
                self.presentColdStartIfNeeded(result)
            }
        } catch { self.error = error.localizedDescription }
    }

    func verifyOriginalAfterStartup() {
        guard originalStartupConfirmed, originalRestoreLastJob != nil, originalRestoreConfirmed else {
            error = "请确认最初备份和本次关开机；恢复检查点必须已安全退出。"; return
        }
        makeDeviceBackup(forRestore: true) { self.executeOriginalRestore(verifyAfterStartup: true) }
    }

    func recordOriginalAcceptance() {
        guard let originalRestoreLastJob, originalRestorePhase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE",
              ColdStartInstructions.canSubmitFinal(phase: originalRestorePhase, safeReceipt: finalColdStartReady,
                coldStart: finalColdStartConfirmed, observations: [originalNamesAccepted, originalSoundAccepted, originalShootAccepted, originalPlaybackAccepted]) else { return }
        do {
            guard let job = try newJob("恢复功能验收") else { return }
            let references: [String: Any] = ["schema": "a7m4-archived-active-references/1",
                "completed_program_jobs": choices.completedProgramJobs ?? [],
                "last_sound_job": choices.lastSoundJob as Any? ?? NSNull(),
                "last_gate_capsule": choices.lastGateCapsule as Any? ?? NSNull(),
                "last_sound_capsule": choices.lastSoundCapsule as Any? ?? NSNull(),
                "last_feature_capsule": choices.lastFeatureCapsule as Any? ?? NSNull(),
                "last_feature_checkpoint": choices.lastFeatureCheckpoint as Any? ?? NSNull(),
                "files_preserved": true]
            try writeJSON(references, to: job.appendingPathComponent("prior-active-references.json"))
            let completedTiming = progress
            run(["driver", "backup-target-acceptance", "--job", originalRestoreLastJob.path,
                 "--output", job.appendingPathComponent("acceptance.json").path,
                 "--names-confirmed", "--sound-confirmed", "--shoot-confirmed", "--playback-confirmed"],
                title: "正在保存功能检查结果…", job: job) { ok, result in
                guard ok, result?["schema"] as? String == "a7m4-backup-target-acceptance/1",
                      result?["status"] as? String == "USER_ACCEPTED_BACKUP_SCOPE_RESTORATION",
                      DriverJobPolicy.strictTrue(result?["complete"]), DriverJobPolicy.strictFalse(result?["camera_io"]),
                      result?["checkpoint_path"] as? String == originalRestoreLastJob.path else { return }
                self.choices.completedProgramJobs = []; self.choices.lastSoundJob = nil
                self.choices.lastGateCapsule = nil; self.choices.lastSoundCapsule = nil
                self.choices.lastFeatureCapsule = nil; self.choices.lastFeatureCheckpoint = nil
                self.choices.lastSelectedJob = nil
                self.choices.featureCheckpointCount = nil; self.choices.featureProgressFraction = nil
                self.choices.featureProgressProfile = nil; self.choices.featureMachineSeconds = nil
                self.choices.featureUserWaitSeconds = nil; self.choices.featureWaitStartedAt = nil
                self.saveChoices()
                self.progress = completedTiming
                self.progress.finish(accepted: true, verifiedComplete: true, checkpoint: false, now: ProcessInfo.processInfo.systemUptime)
                self.originalRestorePhase = "USER_ACCEPTED_BACKUP_SCOPE_RESTORATION"; self.restoreWaitStartedAt = nil; self.saveRestoreProgress()
                self.message = "备份中的受支持功能区域及启动后运行值已核验；用户功能观察已保存。"
            }
        } catch { self.error = error.localizedDescription }
    }

    func checkTailRestoreIntegration() {
        run(["driver", "tail-restore-status"], title: "正在读取本地完整文件收尾接入状态…")
    }

    func sourceSoundURL(_ role: String) -> URL? {
        let key = role == "sha_dry" ? "sha" : role
        if let custom = choices.soundFiles[key] { return URL(fileURLWithPath: custom) }
        if role == "recock" { return assets.appendingPathComponent("m9-recock.wav") }
        let preset = choices.soundPreset
        let prefix = ["dry", "soft"].contains(preset) ? preset : "factory"
        if key == "sha", ["m9", "m9-recock"].contains(preset) { return assets.appendingPathComponent("m9-sha-dry.wav") }
        return assets.appendingPathComponent("\(prefix)-\(key).wav")
    }

    func soundURL(_ role: String) -> URL? { kaShaPreview?.urls[role] }

    func soundErrorText(_ raw: String) -> String {
        let text = raw.lowercased()
        if text.contains("headroom") { return "音量过高，超出可用余量。请降低生成音量后重新试听。" }
        if text.contains("end_seconds") || text.contains("start_seconds") || text.contains("trim") {
            return "裁切范围超出源声音，或起点不早于终点。请检查起点和终点的毫秒数。"
        }
        if text.contains("fade") { return "淡入、淡出各须在 0–20 ms 内，合计不能超过选中声音长度。" }
        if text.contains("sample budget") || text.contains("capacity") || text.contains("exceeds") || text.contains("encoded size") {
            return "生成的声音超过容量。请裁短素材，或缩短固定 KASHA／上弦间隔；不会自动加速声音。"
        }
        if text.contains("wav") { return "无法读取此 WAV。请选择有效、10 秒以内、单声道或双声道的 WAV 文件。" }
        return "声音尚未准备完成，请检查输入文件、音量与间隔设置。"
    }

    func sourceDuration(_ role: String) -> Double {
        guard let url = sourceSoundURL(role), let player = try? AVAudioPlayer(contentsOf: url) else { return 0 }
        return player.duration
    }

    func soundEdit(_ role: String) -> SoundClipEdit {
        if let saved = choices.soundEdits?[role] { return saved }
        let duration = sourceDuration(role)
        return SoundClipEdit(endSeconds: role == "ka" ? min(duration, 248.0 / 24000.0) : duration,
                             fadeOutMS: role == "ka" && duration > 248.0 / 24000.0 ? 1 : 0)
    }

    func setSoundEdit(_ role: String, _ value: SoundClipEdit) {
        var edits = choices.soundEdits ?? [:]
        edits[role] = value
        choices.soundEdits = edits
    }

    func chooseSound(_ role: String) {
        guard ["ka", "sha", "recock"].contains(role) else { return }
        stopAudio()
        guard let url = file("选择 \(role.uppercased()) 声音", types: [.wav]) else { return }
        do {
            let player = try AVAudioPlayer(contentsOf: url)
            guard player.duration > 0, player.duration <= 10 else {
                error = "请选择 10 秒以内的 WAV；可在裁切编辑器中选取需要的片段。"; return
            }
            let target = try copyInput(url, extension: "wav")
            var selected = choices.soundFiles
            for other in ["ka", "sha", "recock"] where other != role && selected[other] == nil {
                if let existing = sourceSoundURL(other) { selected[other] = try copyInput(existing, extension: "wav").path }
            }
            selected[role] = target.path
            choices.soundFiles = selected
            var edits = choices.soundEdits ?? [:]
            edits[role] = SoundClipEdit(endSeconds: role == "ka" ? min(player.duration, 248.0 / 24000.0) : player.duration,
                fadeOutMS: role == "ka" && player.duration > 248.0 / 24000.0 ? 1 : 0)
            choices.soundEdits = edits
            choices.soundPreset = "custom"
            if role == "recock" { choices.recockEnabled = true }
            audioMessage = role == "ka" ? "已选 KA，当前保留前 10.33 ms；可调整裁切位置。" : "已选择声音，请检查裁切范围"
        } catch { self.error = "声音文件无法读取：\(error.localizedDescription)" }
    }

    func setSoundPreset(_ preset: String) {
        guard preset != choices.soundPreset else { return }
        stopAudio()
        choices.soundPreset = preset
        choices.soundFiles = [:]
        choices.soundEdits = nil
        choices.recockEnabled = preset == "m9-recock"
        audioMessage = "已选择音色，正在生成最终原生声音预览"
    }

    func setKaShaSwitchDenominator(_ value: Int) {
        guard UserChoices.kaShaSwitchOptions.contains(value) else { return }
        choices.kaShaSwitchDenominator = value
        if value != 50 { choices.includeCutoffCandidate = false }
    }

    private func soundConfig() throws -> [String: Any] {
        var clips: [String: Any] = [:]
        for role in ["ka", "sha", "recock"] where role != "recock" || choices.effectiveRecockEnabled {
            guard let source = sourceSoundURL(role) else { throw CocoaError(.fileNoSuchFile) }
            let edit = soundEdit(role)
            var clip: [String: Any] = ["path": source.path, "start_seconds": edit.startSeconds,
                "fade_in_ms": edit.fadeInMS, "fade_out_ms": edit.fadeOutMS]
            if let end = edit.endSeconds { clip["end_seconds"] = end }
            clips[role == "sha" ? "sha_dry" : role] = clip
        }
        return ["schema": "a7m4-pin-sound-project/1", "clips": clips,
            "gain_db": choices.effectiveSoundGainDB,
            "recock": ["enabled": choices.effectiveRecockEnabled, "gap_ms": choices.effectiveRecockGapMS],
            "hybrid_cutoff": ["denominator": choices.effectiveKaShaSwitchDenominator],
            "kasha_synthesis": ["link_pair_delay_to_cutoff": choices.effectiveLinkKaShaPairDelay,
                "pair_delay_seconds": choices.effectiveKaShaPairDelayMS / 1000, "preserve_tails": true]]
    }

    func stopKaShaPreview() {
        kaShaTask?.cancel(); kaShaTask = nil
        if let child = soundPreviewProcess, child.isRunning {
            AppDiagnostics.terminate(child, reason: "cancel-or-timeout")
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) } }
        }
        soundPreviewProcess = nil
        kaShaRevision = UUID()
        if let previous = soundPreviewWorkspace { try? FileManager.default.removeItem(at: previous) }
        soundPreviewWorkspace = nil
        kaShaPreview = nil
        kaShaPreparing = false
        soundBudgetSummary = ""
    }

    func scheduleKaShaPreview() {
        stopAudio(); stopKaShaPreview()
        kaShaError = nil; kaShaPreparing = true
        let revision = kaShaRevision
        let directory = support.appendingPathComponent("pin-sound-previews/\(revision.uuidString)", isDirectory: true)
        soundPreviewWorkspace = directory
        kaShaTask = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 300_000_000) } catch { return }
            guard let self, !Task.isCancelled, self.kaShaRevision == revision else { return }
            do {
                let config = try self.soundConfig()
                let python = self.resources.appendingPathComponent("python/bin/python3")
                let runner = self.kit.appendingPathComponent("run_research.py")
                let cwd = self.kit
                let outcome = await Task.detached { [weak self] () -> KaShaPreviewOutcome in
                    do {
                        guard let self else { return KaShaPreviewOutcome(error: "声音任务已结束") }
                        try FileManager.default.createDirectory(at: directory.appendingPathComponent("inputs"), withIntermediateDirectories: true,
                                                                attributes: [.posixPermissions: 0o700])
                        var frozen = config
                        var clips = config["clips"] as! [String: [String: Any]]
                        for (role, var clip) in clips {
                            let source = URL(fileURLWithPath: clip["path"] as! String)
                            let target = directory.appendingPathComponent("inputs/\(role).wav")
                            let info = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                            guard info.isRegularFile == true, let bytes = info.fileSize, bytes <= 16 * 1024 * 1024 else {
                                throw NSError(domain: "PinSound", code: 1, userInfo: [NSLocalizedDescriptionKey: "请使用 16 MiB 以内的本地 WAV 文件。"])
                            }
                            try FileManager.default.copyItem(at: source, to: target)
                            clip["path"] = target.path; clips[role] = clip
                        }
                        frozen["clips"] = clips
                        let input = directory.appendingPathComponent("source-project.json")
                        try JSONSerialization.data(withJSONObject: frozen, options: [.prettyPrinted, .sortedKeys]).write(to: input, options: .withoutOverwriting)
                        let prepared = directory.appendingPathComponent("prepared")
                        let child = Process()
                        child.executableURL = python
                        child.arguments = ["-I", "-B", runner.path, "pin-sound-prepare", input.path, "--output", prepared.path]
                        child.currentDirectoryURL = cwd
                        child.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
                        let pipe = Pipe(); child.standardOutput = pipe; child.standardError = pipe
                        try AppDiagnostics.launch(child)
                        await MainActor.run {
                            if self.kaShaRevision == revision { self.soundPreviewProcess = child } else { AppDiagnostics.terminate(child, reason: "cancel-or-timeout") }
                        }
                        DispatchQueue.global().asyncAfter(deadline: .now() + 60) {
                            if child.isRunning {
                                AppDiagnostics.terminate(child, reason: "timeout")
                                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) } }
                            }
                        }
                        let data = pipe.fileHandleForReading.readDataToEndOfFile(); child.waitUntilExit()
                        AppDiagnostics.output(data, child: child)
                        guard child.terminationStatus == 0 else {
                            let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                            throw NSError(domain: "PinSound", code: 2, userInfo: [NSLocalizedDescriptionKey:
                                result?["error"] as? String ?? "声音未能编码，请检查裁切长度、增益与间隔。"])
                        }
                        let dataManifest = try Data(contentsOf: prepared.appendingPathComponent("manifest.json"))
                        guard let manifest = try JSONSerialization.jsonObject(with: dataManifest) as? [String: Any],
                              manifest["schema"] as? String == "a7m4-prepared-pin-sound-pack/1",
                              let decoded = manifest["decoded"] as? [String: [String: Any]] else { throw CocoaError(.fileReadCorruptFile) }
                        var urls: [String: URL] = [:]
                        for role in ["ka", "sha", "kasha"] {
                            guard let name = decoded[role]?["file"] as? String else { throw CocoaError(.fileReadCorruptFile) }
                            urls[role] = try nativeAssetURL(prepared, name)
                        }
                        return KaShaPreviewOutcome(preview: KaShaPreview(revision: revision, directory: directory,
                            prepared: prepared, urls: urls, manifest: manifest))
                    } catch { return KaShaPreviewOutcome(error: error.localizedDescription) }
                }.value
                guard !Task.isCancelled, self.kaShaRevision == revision else {
                    try? FileManager.default.removeItem(at: directory); return
                }
                self.soundPreviewProcess = nil
                self.kaShaPreparing = false; self.kaShaPreview = outcome.preview; self.kaShaError = outcome.error
                if let preview = outcome.preview, let native = preview.manifest["native"] as? [String: [String: Any]] {
                    self.soundBudgetSummary = ["ka", "sha", "kasha"].map {
                        "\($0.uppercased()) \(native[$0]?["actual_bytes"] as? Int ?? 0) / \(native[$0]?["max_allowed_actual_bytes"] as? Int ?? 0) B"
                    }.joined(separator: " · ")
                    self.audioMessage = "已重新合成并编码；试听来自最终原生数据解码，音量已计入一次"
                }
            } catch {
                guard self.kaShaRevision == revision else { return }
                self.kaShaPreparing = false; self.kaShaError = error.localizedDescription
            }
        }
    }

    private func readyKaShaPreview() throws -> KaShaPreview {
        guard !kaShaPreparing, let preview = kaShaPreview, preview.revision == kaShaRevision else {
            throw NSError(domain: "PinSound", code: 3, userInfo: [NSLocalizedDescriptionKey: kaShaError ?? "正在准备最终声音，请稍后再试。"])
        }
        for section in ["native", "decoded"] {
            guard let records = preview.manifest[section] as? [String: [String: Any]] else { throw CocoaError(.fileReadCorruptFile) }
            for role in ["ka", "sha", "kasha"] {
                guard let row = records[role] else { throw CocoaError(.fileReadCorruptFile) }
                let keys = section == "native" ? [("file", "sha256"), ("slot_file", "slot_sha256")] : [("file", "sha256")]
                for (pathKey, hashKey) in keys {
                    guard let name = row[pathKey] as? String, let expected = row[hashKey] as? String else { throw CocoaError(.fileReadCorruptFile) }
                    let url = try nativeAssetURL(preview.prepared, name)
                    let actual = SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined()
                    guard actual == expected else { throw CocoaError(.fileReadCorruptFile) }
                }
            }
        }
        return preview
    }

    func stopAudio() {
        if let child = groupPreviewProcess, child.isRunning {
            AppDiagnostics.terminate(child, reason: "cancel-or-timeout")
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) } }
        }
        groupPreviewProcess = nil
        auditionID = UUID(); pendingAudio.forEach { $0.cancel() }; pendingAudio = []
        players.forEach { $0.stop() }; players = []
        audioPlaying = false; audioMessage = "试听已停止"
    }

    private func playAudition(_ url: URL, message: String, generation: UUID) throws {
        guard auditionID == generation else { return }
        let player = try AVAudioPlayer(contentsOf: url)
        player.volume = 1 // Gain is already applied once before native encoding.
        player.prepareToPlay(); players = [player]
        guard player.play() else { throw CocoaError(.fileReadUnknown) }
        audioPlaying = true; audioMessage = message
        let finish = DispatchWorkItem {
            guard self.auditionID == generation else { return }
            self.audioPlaying = false; self.audioMessage = "试听完成"; self.players = []; self.pendingAudio = []
        }
        pendingAudio.append(finish)
        DispatchQueue.main.asyncAfter(deadline: .now() + player.duration + 0.1, execute: finish)
    }

    func audition(_ role: String? = nil) {
        stopAudio()
        let generation = auditionID
        do {
            let preview = try readyKaShaPreview()
            if let role {
                guard let url = preview.urls[role] else { throw CocoaError(.fileNoSuchFile) }
                try playAudition(url, message: "正在试听最终 \(role.uppercased())", generation: generation)
                return
            }
            let seconds = choices.shutterSeconds
            let python = resources.appendingPathComponent("python/bin/python3")
            let runner = kit.appendingPathComponent("run_research.py")
            let cwd = kit
            let output = preview.directory.appendingPathComponent("group-\(generation.uuidString).wav")
            audioPlaying = true; audioMessage = "正在从最终原生声音生成整组试听…"
            Task { [weak self] in
                let error = await Task.detached { [weak self] () -> String? in
                    guard let self else { return "试听已结束" }
                    do {
                        let child = Process()
                        child.executableURL = python
                        child.arguments = ["-I", "-B", runner.path, "pin-sound-preview", preview.prepared.path,
                            "--shutter-seconds", String(seconds), "--output", output.path]
                        child.currentDirectoryURL = cwd
                        child.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
                        let pipe = Pipe(); child.standardOutput = pipe; child.standardError = pipe
                        try AppDiagnostics.launch(child)
                        await MainActor.run {
                            if self.auditionID == generation { self.groupPreviewProcess = child } else { AppDiagnostics.terminate(child, reason: "cancel-or-timeout") }
                        }
                        DispatchQueue.global().asyncAfter(deadline: .now() + 60) {
                            if child.isRunning {
                                AppDiagnostics.terminate(child, reason: "timeout")
                                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) } }
                            }
                        }
                        let data = pipe.fileHandleForReading.readDataToEndOfFile(); child.waitUntilExit()
                        AppDiagnostics.output(data, child: child)
                        guard child.terminationStatus == 0 else {
                            let result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                            return result?["error"] as? String ?? "整组试听生成失败，请检查声音余量与播放间隔。"
                        }
                        return nil
                    } catch { return error.localizedDescription }
                }.value
                guard let self, self.auditionID == generation, self.kaShaRevision == preview.revision else { return }
                self.groupPreviewProcess = nil
                if let error {
                    self.stopAudio(); self.report = error; self.error = "整组试听未完成：\(self.soundErrorText(error))"
                } else {
                    do { try self.playAudition(output, message: "正在试听最终原生声音组成的整组节奏", generation: generation) }
                    catch { self.stopAudio(); self.error = error.localizedDescription }
                }
            }
        } catch { self.error = "不能试听：\(error.localizedDescription)" }
    }

    func prepareSound() {
        do {
            let preview = try readyKaShaPreview()
            guard let job = try newJob("原生声音方案") else { return }
            guard preview.revision == kaShaRevision else { throw CocoaError(.fileReadCorruptFile) }
            let saved = job.appendingPathComponent("project")
            try FileManager.default.copyItem(at: preview.directory, to: saved)
            let input = saved.appendingPathComponent("source-project.json")
            var config = try JSONSerialization.jsonObject(with: Data(contentsOf: input)) as! [String: Any]
            var clips = config["clips"] as! [String: [String: Any]]
            for (role, var clip) in clips { clip["path"] = "inputs/\(role).wav"; clips[role] = clip }
            config["clips"] = clips
            try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]).write(to: input, options: .atomic)
            run(["pin-sound-verify", saved.appendingPathComponent("prepared").path],
                title: "正在校验并保存最终原生声音方案…", job: job)
        } catch { self.message = "声音方案未保存完成"; self.error = error.localizedDescription }
    }

    func choosePinImage(_ kind: String) {
        guard let selected = file("选择本地完整\(kind == "ap" ? "应用程序 AP" : kind == "cp_program" ? "成像程序 CP" : "声音库 SysSound.bin")") else { return }
        pinImages[kind] = selected
        pinPlanFile = nil
    }

    func preparePinInstallPlan() {
        do {
            let preview = try readyKaShaPreview()
            guard let ap = pinImages["ap"], let cp = pinImages["cp_program"], let bank = pinImages["bank"],
                  let job = try newJob("声音安装离线计划") else { return }
            let target = job.appendingPathComponent("install-plan.json")
            var args = ["pin-sound-plan", "--ap", ap.path, "--cp-program", cp.path, "--bank", bank.path,
                "--project", preview.prepared.path, "--output", target.path]
            if choices.includeCutoffCandidate == true {
                guard choices.effectiveKaShaSwitchDenominator == 50 else { throw CocoaError(.featureUnsupported) }
                args += ["--cutoff", "50"]
            }
            pinPlanFile = nil
            run(args, title: "正在核对完整前像并生成范围、逆操作与预算…", job: job) { ok, _ in
                if ok { self.pinPlanFile = target }
            }
        } catch { self.error = error.localizedDescription }
    }

    func preparePinWorkers() {
        guard let plan = pinPlanFile else { return }
        do {
            guard let job = try newJob("声音离线安装材料") else { return }
            var args = ["pin-sound-workers", plan.path, "--output", job.appendingPathComponent("bundle").path]
            if let compiler = pinCompiler { args += ["--compiler", compiler.path] }
            run(args,
                title: "正在构建有界声音数据包与离线 helper…", job: job)
        } catch { self.error = error.localizedDescription }
    }

    private func copyInput(_ input: URL, extension suffix: String) throws -> URL {
        let directory = support.appendingPathComponent("imports").appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let target = directory.appendingPathComponent(input.deletingPathExtension().lastPathComponent).appendingPathExtension(suffix)
        try FileManager.default.copyItem(at: input, to: target)
        return target
    }

    func iconText(_ item: FilterChoice) -> String {
        if let text = item.iconText { return text }
        return item.preset == "m9" ? "M9" : "ST"
    }

    func setFilterRecipe(_ id: String, recipe: String) {
        guard RestrictedFilterPolicy.recipes.contains(recipe),
              let index = choices.filters.firstIndex(where: { $0.id == id }),
              recipe != "m9" || index == 0 else { return }
        // Changing the recipe does not replace the independently edited display.
        var item = choices.filters[index]
        item.preset = recipe
        item.cube = nil
        item.checkOnly = false
        choices.filters[index] = item
    }

    func setIconText(_ id: String, text: String) {
        guard let index = choices.filters.firstIndex(where: { $0.id == id }) else { return }
        choices.filters[index].iconText = text
    }

    private func validIconText(_ text: String) -> Bool {
        if text.range(of: "^[A-Za-z0-9]{1,3}$", options: .regularExpression) != nil { return true }
        guard text.unicodeScalars.count == 1, let scalar = text.unicodeScalars.first else { return false }
        return (0x3400...0x4DBF).contains(scalar.value) || (0x4E00...0x9FFF).contains(scalar.value)
            || (0x20000...0x2EE5F).contains(scalar.value) || (0x30000...0x323AF).contains(scalar.value)
    }

    private func nativeRow(_ item: FilterChoice, slot: Int) throws -> [String: Any] {
        let text = iconText(item)
        guard validIconText(text) else {
            throw NSError(domain: "NativeIcons", code: 9, userInfo: [NSLocalizedDescriptionKey:
                "“\(item.label)”的图标文字须为 1–3 个英文字母／数字，或 1 个汉字；保留大小写。"])
        }
        var row: [String: Any] = ["slot": slot, "text": text]
        var pngs: [String: String] = [:]
        if let path = item.normalIcon { pngs["list-normal"] = path }
        if let path = item.selectedIcon { pngs["list-selected"] = path }
        if let path = item.playbackIcon { pngs["playback"] = path }
        if !pngs.isEmpty { row["pngs"] = pngs }
        return row
    }

    func iconURL(_ item: FilterChoice, role: String = "normal", bank: String = "23") -> URL? {
        guard nativePreviewReadyRevision == nativePreviewRevision, !nativePreviewPending,
              nativePreviewError == nil, ["23", "32"].contains(bank) else { return nil }
        return nativeIconURLs[item.id]?[bank == "23" ? role : "32-" + role]
    }

    var iconPreviewNote: String {
        guard let index = choices.filters.firstIndex(where: { $0.id == selectedFilter }) else { return "请选择一个位置。" }
        return choices.filters[index].enabled
            ? "固定位置 \(index + 1) · 预览与导出使用同一批原生位图。"
            : "固定位置 \(index + 1) 未勾选；以下是该位置的草稿，不随当前配置导出。"
    }

    func scheduleNativePreview() {
        guard !ProductIdentity.offlineQA else { return }
        stopNativePreview()
        let revision = nativePreviewRevision
        nativeIconURLs = [:]
        nativeProject = nil
        nativePreviewError = nil
        nativePreviewPending = true
        nativePreviewTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 280_000_000)
            guard !Task.isCancelled, let self, self.nativePreviewRevision == revision else { return }
            do {
                let selected = try RestrictedFilterPolicy.selectedSlots(self.choices.filters)
                var jobs: [NativePreviewJob] = []
                if !selected.isEmpty {
                    var rows: [[String: Any]] = []
                    var ids: [Int: String] = [:]
                    for (slot, item) in selected {
                        rows.append(try self.nativeRow(item, slot: slot))
                        ids[slot] = item.id
                    }
                    jobs.append(NativePreviewJob(config: ["schema": "a7m4-native-icons/1", "slots": rows], itemIDs: ids, name: "active"))
                }
                if let index = self.choices.filters.firstIndex(where: { $0.id == self.selectedFilter && !$0.enabled }) {
                    let draft = self.choices.filters[index]
                    let slot = index + 1
                    jobs.append(NativePreviewJob(config: ["schema": "a7m4-native-icons/1", "slots": [try self.nativeRow(draft, slot: slot)]],
                                                 itemIDs: [slot: draft.id], name: "draft"))
                }
                let cache = self.support.appendingPathComponent("native-icon-cache", isDirectory: true)
                try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                let workspace = cache.appendingPathComponent(revision.uuidString)
                try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                let python = self.resources.appendingPathComponent("python/bin/python3")
                let runner = self.kit.appendingPathComponent("run_research.py")
                let cwd = self.kit
                let outcome = await Task.detached { [weak self] () -> NativePreviewOutcome in
                    var outcome = NativePreviewOutcome()
                    do {
                        for job in jobs {
                            guard let self, await MainActor.run(body: { self.nativePreviewRevision == revision }) else { return outcome }
                            let input = workspace.appendingPathComponent(job.name + "-input.json")
                            let encoded = try JSONSerialization.data(withJSONObject: job.config, options: [.prettyPrinted, .sortedKeys])
                            try encoded.write(to: input, options: .withoutOverwriting)
                            let destination = workspace.appendingPathComponent(job.name)
                            let child = Process()
                            child.executableURL = python
                            child.arguments = ["-I", "-B", runner.path, "native-icons", input.path, "--output", destination.path]
                            child.currentDirectoryURL = cwd
                            child.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"]
                            let pipe = Pipe()
                            child.standardOutput = pipe
                            child.standardError = pipe
                            try AppDiagnostics.launch(child)
                            await MainActor.run {
                                if self.nativePreviewRevision == revision { self.nativePreviewProcess = child }
                                else { AppDiagnostics.terminate(child, reason: "cancel-or-timeout") }
                            }
                            DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
                                if child.isRunning {
                                    AppDiagnostics.terminate(child, reason: "timeout")
                                    DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                                        if child.isRunning { Darwin.kill(child.processIdentifier, SIGKILL) }
                                    }
                                }
                            }
                            let result = pipe.fileHandleForReading.readDataToEndOfFile()
                            child.waitUntilExit()
                            AppDiagnostics.output(result, child: child)
                            guard child.terminationStatus == 0 else {
                                let detail = (try? JSONSerialization.jsonObject(with: result)) as? [String: Any]
                                throw NSError(domain: "NativeIcons", code: Int(child.terminationStatus), userInfo: [NSLocalizedDescriptionKey:
                                    detail?["error"] as? String ?? "图标未能生成，请检查文字、字形和 70×35 PNG 输入。"])
                            }
                            let urls = try readNativeAssets(destination, itemIDs: job.itemIDs)
                            outcome.urls.merge(urls) { _, new in new }
                            if job.name == "active" { outcome.activeProject = destination }
                        }
                    } catch { outcome.error = error.localizedDescription }
                    return outcome
                }.value
                guard !Task.isCancelled, self.nativePreviewRevision == revision else { return }
                self.nativePreviewProcess = nil
                self.nativePreviewPending = false
                self.nativePreviewError = outcome.error
                if outcome.error == nil {
                    self.nativeIconURLs = outcome.urls
                    self.nativeProject = outcome.activeProject
                    self.nativePreviewReadyRevision = revision
                }
            } catch {
                guard self.nativePreviewRevision == revision else { return }
                self.nativePreviewPending = false
                self.nativePreviewError = error.localizedDescription
            }
        }
    }

    func chooseIcon(_ id: String, role: String) {
        guard let index = choices.filters.firstIndex(where: { $0.id == id }),
              let url = file("选择\(role == "normal" ? "普通" : role == "selected" ? "选中" : "回放")位图", types: [.png]) else { return }
        do {
            let data = try Data(contentsOf: url)
            guard data.count <= 8 * 1024 * 1024, data.prefix(8) == Data([137, 80, 78, 71, 13, 10, 26, 10]),
                  let image = NSBitmapImageRep(data: data), image.pixelsWide == 70, image.pixelsHigh == 35 else {
                error = "高级覆盖须为严格 70 × 35 像素、不超过 8 MB 的 PNG；不会自动缩放。"; return
            }
            let target = try copyInput(url, extension: "png")
            if role == "normal" { choices.filters[index].normalIcon = target.path }
            if role == "selected" { choices.filters[index].selectedIcon = target.path }
            if role == "playback" { choices.filters[index].playbackIcon = target.path }
            message = "已保存所选位图"
        } catch { self.error = error.localizedDescription }
    }

    func resetIconOverrides(_ id: String) {
        guard let index = choices.filters.firstIndex(where: { $0.id == id }) else { return }
        var item = choices.filters[index]
        item.normalIcon = nil; item.selectedIcon = nil; item.playbackIcon = nil
        choices.filters[index] = item
    }

    func chooseNativeBankDirectory() {
        guard let selected = folder("选择包含两套本地图标库的目录") else { return }
        let nested = selected.appendingPathComponent("resources", isDirectory: true)
        let root = FileManager.default.fileExists(atPath: selected.appendingPathComponent("image_00_23_IPSX.uxc").path) ? selected : nested
        guard ["23", "32"].allSatisfy({ FileManager.default.fileExists(atPath: root.appendingPathComponent("image_00_\($0)_IPSX.uxc").path) }) else {
            error = "需要同一快照的 image_00_23_IPSX.uxc 和 image_00_32_IPSX.uxc；可选它们所在目录或快照根目录。"
            return
        }
        bankDirectory = root
    }

    func exportNativeBankPlan() {
        guard !nativePreviewPending, nativePreviewError == nil,
              nativePreviewReadyRevision == nativePreviewRevision,
              let project = nativeProject, let banks = bankDirectory else {
            error = "请先完成当前图标预览，并选择两套本地图标库。"; return
        }
        do {
            let selected = try RestrictedFilterPolicy.selectedSlots(choices.filters)
            _ = try readNativeAssets(project, itemIDs: Dictionary(uniqueKeysWithValues: selected.map { ($0.slot, $0.item.id) }))
            guard let job = try newJob("图标资源计划") else { return }
            run(["native-icon-banks", "--bank23", banks.appendingPathComponent("image_00_23_IPSX.uxc").path,
                 "--bank32", banks.appendingPathComponent("image_00_32_IPSX.uxc").path,
                 "--project", project.path, "--output", job.appendingPathComponent("banks").path],
                title: "正在生成本地图标库计划…", job: job)
        } catch { self.error = error.localizedDescription }
    }

    // Shared allowlisted input for project export and the future CLI driver.
    // Device commands are integrated only after their protocol is supplied.
    func filterDriverConfiguration() throws -> [String: Any] {
        _ = try RestrictedFilterPolicy.selectedSlots(choices.filters)
        guard choices.stNoticeAccepted else {
            throw NSError(domain: "RestrictedFilters", code: 3, userInfo: [NSLocalizedDescriptionKey: "请先确认 ST 基底使用须知。"])
        }
        let slots: [[String: Any]] = try choices.filters.enumerated().map { index, item in
            guard !item.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  item.label.unicodeScalars.count <= 32,
                  item.label.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw NSError(domain: "RestrictedFilters", code: 2, userInfo: [NSLocalizedDescriptionKey:
                    "显示名称须为 1–32 个可显示字符。"])
            }
            _ = try nativeRow(item, slot: index + 1)
            return ["slot": index + 1, "selected": item.enabled, "recipe": item.preset,
                    "name": item.label, "icon_text": iconText(item)]
        }
        return ["schema": "a7m4-toolbox-filters/1", "include_fl2": choices.includeFL2,
                "include_fl3": choices.includeFL3, "st_notice_accepted": choices.stNoticeAccepted,
                "slots": slots]
    }

    func saveFilterProject() {
        guard choices.stNoticeAccepted else { error = "请先确认 ST 基底使用须知。"; return }
        guard !nativePreviewPending, nativePreviewError == nil,
              nativePreviewReadyRevision == nativePreviewRevision else {
            error = nativePreviewError ?? "当前图标尚未生成完成；不会保存上一次的旧预览。"; return
        }
        do {
            let driverConfiguration = try filterDriverConfiguration()
            let selected = try RestrictedFilterPolicy.selectedSlots(choices.filters)
            let ids = Dictionary(uniqueKeysWithValues: selected.map { ($0.slot, $0.item.id) })
            if !selected.isEmpty {
                guard let project = nativeProject else { error = "缺少当前已勾选条目的原生图标结果。"; return }
                _ = try readNativeAssets(project, itemIDs: ids)
            }
            guard let job = try newJob("滤镜配置") else { return }
            var exportedAssets: [[String: Any]] = []
            if !selected.isEmpty, let project = nativeProject {
                let destination = job.appendingPathComponent("native-icons")
                try FileManager.default.copyItem(at: project, to: destination)
                _ = try readNativeAssets(destination, itemIDs: ids)
                let data = try Data(contentsOf: destination.appendingPathComponent("manifest.json"))
                guard let manifest = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let assets = manifest["assets"] as? [[String: Any]] else {
                    throw NSError(domain: "NativeIcons", code: 10, userInfo: [NSLocalizedDescriptionKey: "导出的图标清单未能核对，请重新生成。"])
                }
                exportedAssets = assets
            }
            var slots: [[String: Any]] = selected.map { slot, item in
                ["slot": slot, "id": item.id, "name": item.label, "icon_text": iconText(item),
                 "preset": item.preset, "check_only": false, "state": "LOCAL_NATIVE_ASSETS_NOT_APPLIED"]
            }
            for index in slots.indices {
                guard let slot = slots[index]["slot"] as? Int else { continue }
                var bitmaps: [String: String] = [:]
                let roles = ["list-normal": "normal", "list-selected": "selected", "playback": "playback"]
                var nativeResources: [[String: Any]] = []
                for var asset in exportedAssets where asset["slot"] as? Int == slot {
                    if asset["bank_variant"] as? String == "23", let route = asset["route"] as? String,
                       let role = roles[route], let png = asset["png"] as? String {
                        bitmaps[role] = "native-icons/" + png
                    }
                    for key in ["png", "raw", "compressed"] {
                        if let path = asset[key] as? String { asset[key] = "native-icons/" + path }
                    }
                    nativeResources.append(asset)
                }
                slots[index]["icons"] = bitmaps
                slots[index]["native_resources"] = nativeResources
                slots[index]["native_manifest"] = "native-icons/manifest.json"
            }
            let configuration: [String: Any] = ["schema": "a7m4-filter-project/1", "fixed_top": ["FL2", "FL3"],
                "fixed_selected": ["FL2": choices.includeFL2, "FL3": choices.includeFL3], "base": "ST", "runtime_slots": 4,
                "recipe_policy": "PRESERVE_OTHERS_BUILTIN_M9_SLOT1", "filter_uploads_allowed": false,
                "st_notice_confirmed": true, "custom_slots": slots, "driver_selection": "filter-selection.json",
                "native_preview_revision": nativePreviewRevision.uuidString,
                "playback_routes": "CUSTOM1_INDEPENDENT_1E9A_OTHER_SLOTS_PRESERVED", "camera_applied": false, "camera_tests": "NOT_PERFORMED"]
            try writeJSON(driverConfiguration, to: job.appendingPathComponent("filter-selection.json"))
            try writeJSON(configuration, to: job.appendingPathComponent("filters.json"))
            output = job
            message = "滤镜配置和同版原生位图已保存；尚未应用到相机"
            report = "已保存 \(slots.count) 个勾选位置，保留 1–4 固定编号；2–4 槽保持原样，M9 仅第 1 槽／ST。PNG、RGBA4444 与原生压缩资源来自同一版清单。\n相机应用须从应用按钮重新确认备份及风险；本次保存没有设备操作。"
        } catch { self.error = error.localizedDescription }
    }

    var references: [ReferenceLink] {
        let path = kit.appendingPathComponent("a7m4/research/data/references.json")
        if let data = try? Data(contentsOf: path), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let rows = object["references"] as? [[String: Any]] ?? object["sources"] as? [[String: Any]] ?? []
            let links = rows.compactMap { row -> ReferenceLink? in
                guard row["category"] as? String == "upstream-research" else { return nil }
                guard let title = row["name"] as? String ?? row["title"] as? String,
                      let value = row["url"] as? String, let url = URL(string: value),
                      url.scheme == "https" else { return nil }
                return ReferenceLink(title: title, purpose: row["purpose"] as? String ?? "", url: url)
            }
            if !links.isEmpty { return links }
        }
        return [
            ReferenceLink(title: "A7C II FL2/FL3 Research", purpose: "滤镜、声音与资源研究参考",
                          url: URL(string: "https://github.com/QAQLeonard/a7c2-fl23-research")!),
            ReferenceLink(title: "ILCE-7M4-RE", purpose: "机型与启动流程研究参考",
                          url: URL(string: "https://github.com/DavidBuchanan314/ILCE-7M4-RE")!),
            ReferenceLink(title: "Sony-PMCA-RE", purpose: "普通服务协议与 USB 通道的上游研究",
                          url: URL(string: "https://github.com/ma1co/Sony-PMCA-RE")!)
        ]
    }
}

struct HelpTip: View {
    let text: String
    @State private var showing = false
    init(_ text: String) { self.text = text }
    var body: some View {
        Button { showing.toggle() } label: { Image(systemName: "questionmark.circle").foregroundStyle(.secondary) }
            .buttonStyle(.plain).accessibilityLabel("说明").help("说明")
            .popover(isPresented: $showing) { Text(text).font(.callout).padding(16).frame(maxWidth: 350) }
    }
}

struct ProductView: View {
    @StateObject private var model = ProductModel()
    @State private var page = ProductIdentity.offlineQA ?
        (["sequence-install": "安装配置", "sequence-failure": "安装配置", "sequence-restore": "恢复备份", "filters": "安装配置", "sound": "安装配置", "install-cold-start": "安装配置", "install-cold-start-preflight": "安装配置", "restore-target": "恢复备份", "cold-start": "恢复备份", "st-protection": "恢复备份", "st-protection-page": "恢复备份", "final-acceptance": "恢复备份", "final-acceptance-page": "恢复备份", "restore-wait": "恢复备份", "restore-run": "恢复备份", "complete": "恢复备份", "overdue": "安装配置", "about": "参考与关于", "other": "其他功能"][ProductIdentity.qaScenario] ?? "开始与备份") : "开始与备份"
    @State private var installNavigation = UUID()
    @State private var soundExpanded = ProductIdentity.offlineQA && ProductIdentity.qaScenario == "sound"
    @State private var filtersExpanded = ProductIdentity.offlineQA && ProductIdentity.qaScenario == "filters"
    let pages = ["开始与备份", "安装配置", "恢复备份", "其他功能", "参考与关于"]

    var body: some View {
        NavigationSplitView {
            List(pages, id: \.self, selection: $page) { value in
                Label(value, systemImage: symbol(value)).padding(.vertical, 6)
            }.navigationTitle(ProductIdentity.title).navigationSplitViewColumnWidth(min: 170, ideal: 190)
        } detail: {
            VStack(alignment: .leading, spacing: 15) {
                HStack { Text("A7 IV 工具箱"); Spacer(); Text("v" + ProductIdentity.version) }.font(.headline)
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(page).font(.largeTitle.bold())
                        Text("支持目标：A7 IV · ILCE-7M4 · 6.02（执行时按真实读取核验）").foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                Label("开源研究，供个人学习使用。本项目免费，不参与任何收费项目。", systemImage: "info.circle")
                    .font(.callout).frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                if ProductIdentity.offlineQA { Text("离线界面演示 · 不连接相机 · 不代表真实作业结果").font(.caption).foregroundStyle(.orange) }
                if ProductIdentity.offlineQA && ProductIdentity.qaScenario.hasPrefix("sequence-") {
                    Button("推进离线连续样例（第 \(model.offlineSequenceStep + 1) 步）") { model.advanceOfflineSequence() }
                }
                if page == "恢复备份" && model.originalRestorePhase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE" && model.finalColdStartReady {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("最后一步：冷启动并验收功能", systemImage: "exclamationmark.triangle.fill").font(.headline)
                        Text("机内读回与加载核验通过，不代表已替你确认物理冷启动或实际功能。").font(.callout)
                        Text(ColdStartInstructions.finalText).font(.callout.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Button("查看冷启动步骤") { model.coldStartFinalAcceptance = true; model.coldStartNotice = true }
                            Toggle("已按上述步骤完成冷启动", isOn: $model.finalColdStartConfirmed)
                        }
                    }.foregroundStyle(.red).padding(14).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.red.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.red.opacity(0.55)))
                        .disabled(model.running)
                }
                ScrollViewReader { proxy in
                ScrollView {
                    Group {
                        if page == "开始与备份" { preparation }
                        if page == "安装配置" { filters }
                        if page == "恢复备份" { restore }
                        if page == "其他功能" { other }
                        if page == "参考与关于" { references }
                    }.frame(maxWidth: .infinity, alignment: .leading).disabled(model.running)
                }
                .onChange(of: installNavigation) { _, _ in
                    withAnimation { proxy.scrollTo("fixed-install", anchor: .top) }
                }
                }
                Divider()
                if let estimate = model.progress.estimate {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(model.progress.complete ? (estimate.profile == "selected" ? "本次安装已完成" : "本次操作已完成") : "预计机器总用时约 \(estimate.totalMinutes) 分钟")
                            Spacer()
                            Text(model.progress.complete ? "100% · 机器用时 \(Int(model.progress.activeSeconds + model.progress.priorActiveSeconds)) 秒" : "估算 \(Int(model.progress.fraction * 100))% · 已执行 \(Int(model.progress.activeSeconds + model.progress.priorActiveSeconds)) 秒")
                                .monospacedDigit()
                        }.font(.caption).foregroundStyle(.secondary)
                        ProgressView(value: model.progress.fraction).tint(model.progress.complete ? .green : .accentColor)
                        HelpTip("时间仅供参考，取自此前测时的保守估计，并非本版实测；实际以读回与检查结果为准。")
                        if let waitingMessage = model.progress.waitingMessage {
                            Text(waitingMessage)
                                .font(.caption).foregroundStyle(.secondary)
                        } else if model.running && model.progress.overdue {
                            Text("已超过预计机器总用时，任务仍在执行。请等待真实读回与退出结果；不会因此取消或重试。")
                                .font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
                if let warning = model.outputSpaceWarning { Text(warning).font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
                if let warning = model.recordWarning {
                    Text("本地记录提示：" + warning).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                }
                HStack {
                    if model.running { ProgressView().controlSize(.small) }
                    Text(model.message).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                    Spacer()
                    if model.running && !model.deviceJobRunning { Button("停止") { model.stop() } }
                    if model.audioPlaying { Button("停止试听") { model.stopAudio() } }
                }
            }.padding(25).frame(minWidth: 740, minHeight: 640)
        }
        .background(DeviceWindowCloseGuard().frame(width: 0, height: 0))
        .sheet(isPresented: $model.coldStartNotice) {
            VStack(alignment: .leading, spacing: 18) {
                Text(model.coldStartForSTProtection ? "ST 已保存：请冷启动后继续恢复" : model.coldStartForInstallation ? "安装后：冷启动与功能检查" : model.coldStartFinalAcceptance ? "最后一步：冷启动与功能验收" : "需要按步骤冷启动").font(.title2.bold())
                Text(model.coldStartForSTProtection ? ColdStartInstructions.stProtectionText : model.coldStartForInstallation ? "相机通信已安全退出。请按步骤冷启动；实际安装结果以本次报告为准。" : model.coldStartFinalAcceptance ? "机内读回与加载核验通过，通信已安全退出。请亲自完成物理冷启动与功能检查。" : "本阶段已完成核验并退出相机通信。此节点不等于功能验收完成。").foregroundStyle(.red)
                Text(model.coldStartForInstallation || model.coldStartFinalAcceptance ? ColdStartInstructions.finalText : ColdStartInstructions.text).font(.body.weight(.semibold)).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                Text(model.coldStartForInstallation ? "请检查所选声音、滤镜名称图标、拍照与回放；本次安装无需按恢复节点继续。下次修改前，先从原始备份恢复。" : model.coldStartFinalAcceptance ? "最终验收无需立即接回 MSC。完成后回到本页，先确认已冷启动，再勾选四项实际观察。机读证据不会代替这些人工确认。" : "操作后回到本页，勾选已完成并回到 MSC，再继续。应用仍会核对新的启动、加载和必要依赖，不会仅凭等待时间判断完成。")
                    .font(.callout).foregroundStyle(.secondary)
                Text(model.coldStartStepConfirmation.started ? "请仔细完成以上全部红字步骤，完成后再点击右侧按钮。" : "先点击左侧按钮开始操作；完成以上全部红字步骤后，再点击右侧确认。")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button("好的，我去按照红字操作") { model.startColdStartSteps() }
                        .disabled(model.coldStartStepConfirmation.started)
                    Spacer()
                    Button("我已按照红字仔细操作完成") { model.confirmColdStartStepsCompleted() }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.coldStartStepConfirmation.canComplete)
                }
            }.padding(24).frame(width: 620).interactiveDismissDisabled(true)
                .onAppear { model.coldStartStepConfirmation.reset() }
        }
        .sheet(item: $model.applicationReview, onDismiss: { model.applicationReview = nil }) { review in
            ApplicationConfirmationSheet(review: review,
                cancel: { model.applicationReview = nil },
                confirm: { backup, nonboot, ownRisk in
                    model.finishApplicationReview(review.id, backup: backup, nonboot: nonboot, ownRisk: ownRisk)
                }).id(review.id)
        }
        .alert("未能完成", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("好") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
            model.stopAudio(); model.stop(); model.stopNativePreview(); model.stopKaShaPreview()
        }
        .task {
            if ProductIdentity.offlineQA { model.applyOfflineVisualFixture(); return }
            if !model.dependencyChecked { model.checkDependencies() }
            model.scheduleNativePreview()
            model.scheduleKaShaPreview()
        }
    }

    private func symbol(_ value: String) -> String {
        ["开始与备份": "externaldrive.badge.checkmark", "安装配置": "slider.horizontal.3", "快门声音": "speaker.wave.2", "滤镜": "camera.filters",
         "恢复备份": "arrow.uturn.backward", "其他功能": "ellipsis.circle", "参考与关于": "books.vertical"][value] ?? "circle"
    }

    private func card<Content: View>(_ title: String, number: String? = nil, @ViewBuilder content: () -> Content) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 13) {
                HStack {
                    if let number { Text(number).font(.headline).foregroundStyle(.white).frame(width: 26, height: 26).background(Color.accentColor, in: Circle()) }
                    Text(title).font(.headline)
                }
                content()
            }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var preparation: some View {
        VStack(alignment: .leading, spacing: 16) {
            DisclosureGroup("新 Mac 安装与权限") {
                Text("仅Apple Silicon（arm64），macOS14.0或更高；最低版本是构建要求，旧机实测为macOS26.3。Intel不支持。应用自带Python、USB依赖与Zig，无需安装Homebrew、Xcode或Python。")
                Text("从DMG拖到Applications后打开。未签名／未公证包按系统正规提示处理；目录访问在系统要求时授权。首次设备操作在Terminal输入系统sudo密码，请保持电脑与相机连接，仅在应用明确提示冷启动时按指引断开。后台绑定本次App，退出撤销。")
                Text("新Mac请创建或导入完整.a7capture；不要迁移旧preferences或进行中的job/checkpoint，跨Mac续接未验证。导入只校验本地备份，不代表当前相机已连接或版本匹配。")
            }.font(.caption).foregroundStyle(.secondary)
            Text("先确认运行环境和相机，再备份可能受影响的全部对象。").foregroundStyle(.secondary)
            card("检查应用运行环境", number: "1") {
                Text("应用自带所需运行环境，无需另外安装 Python。")
                HStack {
                    Button(model.dependencyChecked ? "重新检查" : "检查环境") { model.checkDependencies() }
                    if model.dependencyChecked {
                        Label(model.dependencyOK ? "本地环境可用" : "环境检查未通过",
                              systemImage: model.dependencyOK ? "checkmark.circle.fill" : "exclamationmark.circle")
                            .foregroundStyle(model.dependencyOK ? .green : .orange)
                    }
                }
            }
            card("准备连接相机", number: "2") {
                Toggle("我已检查相机电量，确认电池充足", isOn: $model.batteryConfirmed)
                Text("在相机中把 USB 连接模式设为“大容量存储（MSC）”，再用可传输数据的 USB 线连接 Mac。")
                Text("保持 Mac 解锁，并在系统提示中选择“允许配件连接”。相机重新枚举时，系统可能再次询问；本工具不能代替你授予系统许可。")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("我已切换到 MSC 模式", isOn: $model.mscConfirmed)
                Button("只读检查连接") { model.checkConnection() }.disabled(model.running)
                Text(model.connectionSummary).font(.caption).foregroundStyle(model.connectionReady ? .green : .secondary)
                HStack {
                    Label(model.cameraObservation, systemImage: "cable.connector").foregroundStyle(.secondary)
                }
                Text("型号、版本和原件身份会在本次备份读取中核对。历史基线与环境检查不表示当前相机已连接。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            card("创建完整便携备份", number: "3") {
                HStack { Text("保存可恢复的原始备份，并校验读取结果。"); HelpTip("备份覆盖受影响的程序、滤镜显示资源、声音与完整原始设置。完成后另行确认相机已安全返回 MSC；数据和失败记录会保留。") }
                HStack {
                    Button("从相机创建备份") { model.makeDeviceBackup() }.disabled(!model.canCaptureDeviceBackup)
                    Text(model.backupReadinessNote).font(.caption).foregroundStyle(.secondary)
                }
                Button("选择并校验完整备份…") { model.chooseAndVerifyBackup() }.disabled(model.running)
                if model.backupImportRunning {
                    HStack(alignment: .top, spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(model.backupImportSummary).font(.callout)
                    }.accessibilityElement(children: .combine)
                } else if !model.backupImportSummary.isEmpty {
                    Label(model.backupImportSummary, systemImage: model.backupImportFailed ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .font(.callout).foregroundStyle(model.backupImportFailed ? .red : .green)
                }
                Button("接纳已有 capture 文件夹…") { model.chooseCaptureFolder() }.disabled(model.running)
                Text(model.captureSummary).font(.caption).foregroundStyle(.secondary)
                Text("返回确认可能等待系统允许配件连接或 MSC，最多 60 秒；到时已验证数据仍保留。")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("保存完整备份到…") { model.exportCaptureData() }.disabled(!model.backupDataVerified || model.running)
                    if model.backupDataVerified && !model.backupVerified {
                        Button("确认当前 MSC 并继续") { model.confirmMSCAndContinue() }.disabled(model.running)
                    }
                }
                if !model.backupDataVerified {
                    Text("保存前需要创建或导入完整备份，并通过本地数据校验。").font(.caption).foregroundStyle(.secondary)
                }
                Button("在 Finder 显示备份") { model.revealBackup() }.disabled(model.selectedBackup == nil)
                if model.selectedBackup == nil { Text("先选择或创建一份备份，才能在 Finder 中显示。").font(.caption).foregroundStyle(.secondary) }
                Text("作业与完整备份保存在应用私有目录。备份完成后可在 Finder 中查看。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("恢复仅处理本工具拥有的程序、资源及设置位置。此备份不覆盖全芯片或无法启动后的救援。")
                    .font(.caption).foregroundStyle(.red)
                Text("即使备份，依然有可能变砖")
                    .font(.caption).foregroundStyle(.red)
            }
        }
    }

    private var sound: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("试听来自最终编码数据。安装采用本次封存的素材、音量与上弦设置。")
            card("声音素材") {
                Picker("音色", selection: Binding(get: { model.choices.soundPreset }, set: { model.setSoundPreset($0) })) {
                    Text("原厂电子快门 · 本地重合成").tag("factory")
                    Text("M9 · 无上弦 · 本地重合成").tag("m9")
                    Text("M9 · 上弦 · 本地重合成").tag("m9-recock")
                    Text("干脆双帘 · 合成样例").tag("dry")
                    Text("低沉短促 · 合成样例").tag("soft")
                    Text("自选声音文件").tag("custom")
                }.frame(maxWidth: 450)
                ForEach(["ka", "sha"], id: \.self) { role in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(role == "ka" ? "KA · 快门开始" : "SHA · 快门结束（干声）")
                                Text(model.sourceSoundURL(role)?.lastPathComponent ?? "未选择").font(.caption).foregroundStyle(.secondary)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            Button("选择 WAV") { model.chooseSound(role) }
                            Button("试听最终声音") { model.audition(role) }.disabled(model.kaShaPreparing || model.soundURL(role) == nil)
                        }
                    }.padding(.vertical, 5)
                }
                HStack { Text("选择短 WAV 素材后试听。"); HelpTip("KA 的长度有机身格式限制；超出容量会提示。试听、导出与安装采用本次封存的同一批最终原生声音字节。") }
                    .font(.caption).foregroundStyle(.secondary)
            }
            card("音量与上弦") {
                HStack {
                    Text("生成音量").frame(width: 75, alignment: .leading)
                    Slider(value: Binding(get: { model.choices.effectiveSoundGainDB }, set: { model.choices.soundGainDB = $0 }), in: -36...6, step: 0.5)
                        .frame(maxWidth: 330)
                    Text(String(format: "%+.1f dB", model.choices.effectiveSoundGainDB)).monospacedDigit().frame(width: 75)
                    Button("原音量") { model.choices.soundGainDB = 0 }
                }
                Text("0 dB 保留源素材音量。试听已包含此增益；若超出可用余量，请降低音量后重新试听。不会改变机内全局或对焦音量。")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("加入上弦声音", isOn: Binding(get: { model.choices.effectiveRecockEnabled }, set: { model.choices.recockEnabled = $0 }))
                if model.choices.effectiveRecockEnabled {
                    HStack {
                        Text(model.sourceSoundURL("recock")?.lastPathComponent ?? "未选择上弦声音").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("选择上弦 WAV") { model.chooseSound("recock") }
                    }
                    HStack {
                        Text("SHA 结束 → 上弦").frame(width: 125, alignment: .leading)
                        Slider(value: Binding(get: { model.choices.effectiveRecockGapMS }, set: { model.choices.recockGapMS = $0 }), in: 0...80, step: 1)
                            .frame(maxWidth: 300)
                        Text("\(Int(model.choices.effectiveRecockGapMS)) ms").monospacedDigit().frame(width: 65)
                        Button("40 ms") { model.choices.recockGapMS = 40 }
                    }
                    Text("所选间隔会用于最终声音生成和安装。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            card("分段分界与固定 KASHA") {
                Text("机内分界仅支持原厂1/8秒，或已登记的1/50秒候选（本版未完成真机验收）。")
                    .font(.callout).foregroundStyle(.secondary)
                Picker("机内分段分界", selection: Binding(get: { model.choices.effectiveKaShaSwitchDenominator }, set: { model.setKaShaSwitchDenominator($0) })) {
                    ForEach(UserChoices.kaShaSwitchOptions, id: \.self) { denominator in
                        Text(denominator == 50 ? "1/50 秒（候选，待真机验证）" : "1/8 秒（原厂分界）").tag(denominator)
                    }
                }.frame(width: 350)
                Text("等于或快于 1/\(model.choices.effectiveKaShaSwitchDenominator) 秒播放固定 KASHA；更慢时先 KA，曝光结束再 SHA。")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Text("固定 KASHA：KA 开始 → SHA 开始固定 20 ms，与机内分界独立。")
                    Spacer()
                    Button("重新生成") { model.scheduleKaShaPreview() }
                    Button("试听固定 KASHA") { model.audition("kasha") }.disabled(model.kaShaPreparing || model.soundURL("kasha") == nil)
                }
                Text(model.kaShaPreparing ? "正在裁切、合成、编码并解码预览…" : model.soundBudgetSummary)
                    .font(.caption).foregroundStyle(.secondary)
                if !model.kaShaPreparing && model.soundURL("kasha") == nil {
                    Text("试听与保存前需要选择有效的 KA／SHA 声音，并成功生成固定 KASHA。").font(.caption).foregroundStyle(.secondary)
                }
                if let error = model.kaShaError {
                    Text(model.soundErrorText(error)).font(.callout).foregroundStyle(.red)
                    DisclosureGroup("错误详情") { Text(error).font(.caption).textSelection(.enabled) }
                }
                Text("改变声音或间距后，会重新生成固定 KASHA。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            card("试听整组节奏") {
                HStack {
                    Picker("快门速度", selection: $model.choices.shutterSeconds) {
                        Text("1/1000 秒").tag(0.001)
                        Text("1/125 秒").tag(0.008)
                        Text("1/60 秒").tag(1.0 / 60.0)
                        Text("1/50 秒").tag(0.02)
                        Text("1/30 秒").tag(1.0 / 30.0)
                        Text("1/8 秒").tag(0.125)
                        Text("1/4 秒").tag(0.25)
                        Text("1 秒").tag(1.0)
                        Text("2 秒").tag(2.0)
                    }.frame(width: 220)
                    Button("试听这一组") { model.audition() }.buttonStyle(.borderedProminent)
                        .disabled(model.kaShaPreparing || model.soundURL("kasha") == nil)
                    if model.audioPlaying { Button("停止试听") { model.stopAudio() } }
                }
                Text(model.audioMessage).font(.caption).foregroundStyle(.secondary)
            }
            card("保存声音方案") {
                HStack {
                    Button("导出声音方案") { model.prepareSound() }.disabled(model.kaShaPreparing || model.soundURL("kasha") == nil)
                }
                Text("声音导出与安装共用当前最终生成结果；在顶部“准备并应用本次最终选择”封存并安装。").font(.caption).foregroundStyle(.secondary)
                Text("每次修改前请先从原始备份恢复。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var filters: some View {
        VStack(alignment: .leading, spacing: 16) {
            card("便捷预设与最终选择") {
                ForEach(["1", "2", "3"], id: \.self) { preset in
                    Button { model.fillSelectedPreset(preset) } label: {
                        HStack {
                            Image(systemName: model.selectedPreset == preset ? "checkmark.circle.fill" : "circle")
                            Text(["1": "1 · FL2／FL3＋M9 · M9 上弦声音", "2": "2 · FL2／FL3 · M9 无上弦声音", "3": "3 · FL2／FL3 · 无声音（静音）"][preset]!)
                            Spacer()
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.buttonStyle(.bordered)
                }
                Text("预设只填入下方配置。展开编辑后，以本次最终选择和生成的声音、名称图标为准。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("每次需要修改前请先恢复到原始备份").font(.callout.bold()).foregroundStyle(.red)
                Button("选择并校验修改前的原始备份…") { model.chooseOriginalRestoreBackup() }
                if let original = model.originalRestoreArchive { Text(original.lastPathComponent).font(.caption) }
                Toggle("我确认这是任何修改前保存的原始完整备份", isOn: $model.originalRestoreConfirmed)
                Text("滤镜：\(model.choices.includeFL2 && model.choices.includeFL3 ? "FL2／FL3" : "无 FL2／FL3") · \(model.choices.filters.first?.enabled == true ? "M9＋当前名称图标" : "无 M9")；声音：\(model.selectedSoundEnabled ? model.choices.soundPreset : "无（静音）")")
                    .font(.callout)
                Button("准备并应用本次最终选择…") { model.requestApplicationReview("最终选择安装") }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.connectionReady || model.originalRestoreReceipt == nil || !model.originalRestoreConfirmed || model.selectedInstallResultUnknown)
                Text(model.selectedInstallReadiness).font(.caption).foregroundStyle(.secondary)
                if !model.selectedSnapshotSummary.isEmpty { Text("已封存：" + model.selectedSnapshotSummary).font(.caption) }
                HelpTip("执行前重新读取当前状态。已登记区域若不是原始基线，会停止并要求先恢复。仅安装本次完整选择，不叠加旧配置；第2–4槽保持原始基线。")
            }.id("fixed-install")
            DisclosureGroup("声音 · 最终安装配置", isExpanded: $soundExpanded) {
                Picker("电子快门声音", selection: Binding(get: { model.choices.selectedSoundInstallMode ?? "prepared" }, set: { model.choices.selectedSoundInstallMode = $0 })) {
                    Text("安装下方最终声音").tag("prepared")
                    Text("无（静音）").tag("none")
                }.padding(.vertical, 8)
                if model.selectedSoundEnabled { sound }
                else { Text("原始基线保持电子快门静音。此次不安装声音资源，也不启用电子快门声。").font(.caption).foregroundStyle(.secondary) }
            }.padding(14).background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
            DisclosureGroup("滤镜 · 最终安装配置", isExpanded: $filtersExpanded) {
                Toggle("安装 FL2／FL3", isOn: Binding(get: { model.choices.includeFL2 && model.choices.includeFL3 }, set: { model.choices.includeFL2 = $0; model.choices.includeFL3 = $0 }))
                    .padding(.vertical, 8)
                filterEditor
            }.padding(14).background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
        }
    }

    private var filterEditor: some View {
        VStack(alignment: .leading, spacing: 16) {
            card("使用须知 · ST 基底") {
                Text("M9配方使用第1槽的ST基底；安装会按需自动处理，不必手动改机身。名称与图标可独立编辑，第2–4槽保持原始基线。")
                Toggle("我已阅读第 1 槽 M9 的 ST 基底须知", isOn: $model.choices.stNoticeAccepted)
            }
            Group {
                card("四槽显示 · M9 仅第 1 槽") {
                    HStack {
                        Button("重置四槽显示与配方") {
                            model.choices.filters = UserChoices.initial.filters
                            model.selectedFilter = model.choices.filters.first?.id ?? ""
                        }
                        Spacer()
                        Text("本版只修改第 1 槽；2–4 槽保持原样").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(Array(model.choices.filters.enumerated()), id: \.element.id) { index, item in
                        HStack(spacing: 12) {
                            if index == 0 {
                                Toggle("安装 M9 · 自定义1", isOn: $model.choices.filters[index].enabled).frame(width: 95, alignment: .leading)
                            } else { Text("自定义\(index + 1)").frame(width: 95, alignment: .leading) }
                            if index == 0 {
                                BitmapPreview(url: model.iconURL(item)).frame(width: 70, height: 35)
                                Button(item.label) { model.selectedFilter = item.id }.buttonStyle(.plain)
                            } else {
                                Image(systemName: "lock").frame(width: 70, height: 35).foregroundStyle(.secondary)
                                Text("保持现有位置 \(index + 1)").foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(index == 0 ? "显示编辑" : "保持现有").font(.caption).foregroundStyle(.secondary)
                            if index == 0 { Button("编辑") { model.selectedFilter = item.id } }
                        }.padding(8).background(model.selectedFilter == item.id ? Color.accentColor.opacity(0.08) : .clear,
                                                in: RoundedRectangle(cornerRadius: 8))
                    }
                    Text("显示名称、文字和三态位图可独立编辑。未勾选位置不导出，其他位置不会重新编号。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let index = model.choices.filters.firstIndex(where: { $0.id == model.selectedFilter }) {
                    card("编辑位置 \(index + 1)") {
                        Text("勾选自定义1时安装 M9 配方及此处名称图标，不改变第2–4槽。")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("名称与图标随本次 M9 选择封存，安装采用当前六张原生预览快照。")
                            .font(.caption).foregroundStyle(.secondary)
                        TextField("显示名称", text: $model.choices.filters[index].label).textFieldStyle(.roundedBorder).frame(maxWidth: 300)
                        HStack(alignment: .center, spacing: 12) {
                            Text("图标文字")
                            TextField("ST", text: Binding(
                                get: { model.iconText(model.choices.filters[index]) },
                                set: { model.setIconText(model.selectedFilter, text: $0) }))
                                .textFieldStyle(.roundedBorder).frame(width: 105)
                            Text("1–3 个英文字母／数字，或 1 个汉字；保留大小写并自动适配大小")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        HStack(spacing: 28) {
                            ForEach(["normal", "selected", "playback"], id: \.self) { role in
                                VStack(spacing: 7) {
                                    Text(role == "normal" ? "列表普通" : role == "selected" ? "列表选中" : "照片回放").font(.caption)
                                    BitmapPreview(url: model.iconURL(model.choices.filters[index], role: role)).frame(width: 140, height: 70)
                                }
                            }
                        }
                        DisclosureGroup("查看另一套机内图标") {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(spacing: 28) {
                                    ForEach(["normal", "selected", "playback"], id: \.self) { role in
                                        VStack(spacing: 7) {
                                            Text(role == "normal" ? "列表普通" : role == "selected" ? "列表选中" : "照片回放").font(.caption)
                                            BitmapPreview(url: model.iconURL(model.choices.filters[index], role: role, bank: "32"))
                                                .frame(width: 140, height: 70)
                                        }
                                    }
                                }
                                Text("两套均会导出，边框差异来自机内原生资源。")
                                    .font(.caption).foregroundStyle(.secondary)
                            }.padding(.top, 8)
                        }
                        Text(model.iconPreviewNote).font(.caption).foregroundStyle(.secondary)
                        if model.nativePreviewPending {
                            HStack { ProgressView().controlSize(.small); Text("正在生成同版三态原生位图…").font(.caption) }
                        }
                        if let error = model.nativePreviewError {
                            Text("图标未能生成：\(error)").font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                        }
                        Text("第 1 槽使用独立回放图标；其余位置保持原样。预览来自本次将导入的原生位图解码结果；本版可编辑显示路径待在下一台相机检查。")
                            .font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("高级：覆盖三态 PNG") {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("仅接受严格 70 × 35 像素 PNG。覆盖也会经过同一原生编码与解码，预览不会直接显示未处理的输入。")
                                    .font(.caption).foregroundStyle(.secondary)
                                HStack {
                                    ForEach(["normal", "selected", "playback"], id: \.self) { role in
                                        Button(role == "normal" ? "普通 PNG…" : role == "selected" ? "选中 PNG…" : "回放 PNG…") {
                                            model.chooseIcon(model.selectedFilter, role: role)
                                        }
                                    }
                                    Button("恢复文字生成") { model.resetIconOverrides(model.selectedFilter) }
                                }
                            }.padding(.top, 8)
                        }
                    }.disabled(index != 0)
                }
                card("导出图标") {
                    HStack {
                        Button("导出图标资源") { model.saveFilterProject() }.buttonStyle(.borderedProminent)
                            .disabled(model.nativePreviewPending || model.nativePreviewError != nil)
                    }
                    if model.nativePreviewPending { Text("正在生成原生图标预览，完成后才能保存。").font(.caption).foregroundStyle(.secondary) }
                    if let error = model.nativePreviewError { Text("保存前请修正图标错误：" + error).font(.caption).foregroundStyle(.red) }
                    Text("要写入相机，请在顶部“准备并应用本次最终选择”封存并确认。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }.disabled(!model.choices.stNoticeAccepted)
        }
    }

    private var restore: some View {
        let hasCheckpoint = model.originalRestoreLastJob != nil
        let awaitingAcceptance = model.originalRestorePhase == "POST_STARTUP_VERIFIED_AWAITING_USER_ACCEPTANCE"
        let accepted = model.originalRestorePhase == "USER_ACCEPTED_BACKUP_SCOPE_RESTORATION"
        return VStack(alignment: .leading, spacing: 16) {
            card("从备份恢复") {
                Text("选择任何修改之前保存的原始 .a7capture。应用会按需读取当前机身状态，将已支持功能区域恢复为所选备份中的值，保留其他当前数据。不需要旧安装作业、安装顺序或本次 App 中的安装记录。")
                    .font(.callout).foregroundStyle(.secondary)
                Button("选择并校验原始备份…") { model.chooseOriginalRestoreBackup() }
                if let archive = model.originalRestoreArchive {
                    Label(archive.lastPathComponent, systemImage: "externaldrive.badge.checkmark").font(.callout)
                }
                if model.backupImportRunning {
                    HStack { ProgressView().controlSize(.small); Text(model.backupImportSummary).font(.callout) }
                } else if !model.backupImportSummary.isEmpty {
                    Text(model.backupImportSummary).font(.caption).foregroundStyle(model.backupImportFailed ? .red : .secondary)
                }
                Toggle("我确认这是任何修改之前保存的原始完整备份", isOn: $model.originalRestoreConfirmed)
                Text("支持 FL2／FL3、自定义1 M9及名称图标、电子快门声相关的已登记位置。声音目标限原始 77504 字节原厂描述符布局；已修改的声音备份和未知资源布局会明确拒绝。此功能不提供全芯片回滚或无法启动后的救援。")
                    .font(.caption).foregroundStyle(.secondary)
                if hasCheckpoint && !awaitingAcceptance && !accepted {
                    Text("恢复进度已保存在本机，中间节点不是完成。" + ColdStartInstructions.text)
                        .font(.callout).foregroundStyle(.red)
                    Toggle("已完成上述冷启动步骤，并重新进入 MSC", isOn: $model.originalStartupConfirmed)
                }
                if !awaitingAcceptance && !accepted {
                    Button(hasCheckpoint ? "按节点继续从备份恢复…" : "读取当前状态并从备份恢复…") {
                        model.requestApplicationReview("从备份恢复")
                    }.disabled(model.originalRestoreReceipt == nil || !model.originalRestoreConfirmed ||
                        !model.connectionReady || !model.canCaptureDeviceBackup || hasCheckpoint && !model.originalStartupConfirmed ||
                        model.originalRestorePhase == "STOP_UNKNOWN" || model.originalRestorePhase == "STOPPED_RESULT_DELIVERY")
                    Text(model.backupTargetReadinessNote).font(.caption).foregroundStyle(.secondary)
                }
                Text("当前阶段：" + model.backupTargetPhaseText).font(.caption).textSelection(.enabled)
                Text("每次恢复前均需重新确认备份、变砖风险及自行承担风险。写入后先核验读回与安全退出，再按实际需要提示重启；中间节点不等于恢复完成。")
                    .font(.caption).foregroundStyle(.red)
            }
            if awaitingAcceptance && model.finalColdStartReady {
                card("确认启动和拍摄正常") {
                    Text("先完成顶部冷启动步骤并确认，再在机身检查以下项目。")
                    Toggle("名称与图标显示正常", isOn: $model.originalNamesAccepted)
                    Toggle("快门声音表现正常", isOn: $model.originalSoundAccepted)
                    Toggle("实际拍摄正常", isOn: $model.originalShootAccepted)
                    Toggle("照片回放正常", isOn: $model.originalPlaybackAccepted)
                    Button("确认启动和拍摄正常") { model.recordOriginalAcceptance() }
                        .disabled(!model.finalColdStartConfirmed || !model.originalNamesAccepted || !model.originalSoundAccepted || !model.originalShootAccepted || !model.originalPlaybackAccepted)
                    Text("冷启动确认和四项实际观察均完成后，才能保存检查结果。").font(.caption).foregroundStyle(.secondary)
                }.disabled(!model.finalColdStartConfirmed)
            }
            if awaitingAcceptance && !model.finalColdStartReady {
                Text("最终验收收据尚未通过安全退出核对，请先导出诊断供检查；不会提示拔线或提交验收。").foregroundStyle(.red)
            }
            if accepted { Label("备份功能区域恢复与用户功能检查已完成", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
        }
    }

    private var other: some View {
        VStack(alignment: .leading, spacing: 16) {
            card("诊断报告") {
                HStack { Text("一个 ZIP，包含本次启动及全部保留的历史日志和报告。"); HelpTip("不包含固件、照片、音频、备份、原始设置、USB 数据或凭据，不自动上传。旧版已删除或截断的内容无法找回。") }
                    .font(.caption).foregroundStyle(.secondary)
                Button("导出诊断报告…") { model.exportAllDiagnostics() }.disabled(model.running)
                if model.running { Text("请等待当前操作完成后再导出。").font(.caption).foregroundStyle(.secondary) }
            }
        }
    }

    private var references: some View {
        VStack(alignment: .leading, spacing: 16) {
            card("免费、开源、个人学习") {
                Text("本项目是开源研究成果的个人学习工具，免费提供，不参与任何收费项目。当前仅面向内部试用。")
                Text("版本 v\(ProductIdentity.version)（构建 \(ProductIdentity.iteration)）")
                    .font(.callout).foregroundStyle(.secondary)
            }
            card("上游研究") {
                ForEach(model.references) { item in
                    VStack(alignment: .leading, spacing: 4) {
                        Link(item.title, destination: item.url)
                        if !item.purpose.isEmpty { Text(item.purpose).font(.caption).foregroundStyle(.secondary) }
                    }.padding(.vertical, 4)
                }
            }
            card("使用说明") {
                Button("研究知识地图") { NSWorkspace.shared.open(ProductIdentity.knowledgeMapURL) }
                Button("打开使用说明") { NSWorkspace.shared.open(model.kit.appendingPathComponent("docs/user-guide.zh-CN.md")) }
                Text("本项目的方法与资源参考上游研究；来源见上方条目。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            DisclosureGroup("许可与必要声明") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("完整许可与必要声明随包保留，适用于各自的上游代码和资源。")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("查看随包许可与声明") { NSWorkspace.shared.open(model.kit.appendingPathComponent("THIRD_PARTY_NOTICES.md")) }
                }.padding(.top, 8)
            }
        }
    }
}

struct SoundTrimEditor: View {
    @ObservedObject var model: ProductModel
    let role: String
    var body: some View {
        DisclosureGroup("裁切与淡入淡出 · \(String(format: "%.2f", model.soundEdit(role).startSeconds * 1000))–\(String(format: "%.2f", (model.soundEdit(role).endSeconds ?? model.sourceDuration(role)) * 1000)) ms") {
            VStack(alignment: .leading, spacing: 10) {
                SoundWaveform(url: model.sourceSoundURL(role), start: model.soundEdit(role).startSeconds,
                    end: model.soundEdit(role).endSeconds ?? model.sourceDuration(role), duration: model.sourceDuration(role))
                    .frame(height: 55)
                HStack {
                    Text("起点 ms")
                    TextField("起点", value: Binding(get: { model.soundEdit(role).startSeconds * 1000 }, set: {
                        var edit = model.soundEdit(role); edit.startSeconds = $0 / 1000; model.setSoundEdit(role, edit)
                    }), format: .number).frame(width: 90)
                    Text("终点 ms")
                    TextField("终点", value: Binding(get: { (model.soundEdit(role).endSeconds ?? model.sourceDuration(role)) * 1000 }, set: {
                        var edit = model.soundEdit(role); edit.endSeconds = $0 / 1000; model.setSoundEdit(role, edit)
                    }), format: .number).frame(width: 90)
                    Spacer()
                    Button(role == "ka" ? "前 10.33 ms" : "全选") {
                        model.setSoundEdit(role, SoundClipEdit(endSeconds: role == "ka" ? min(model.sourceDuration(role), 248.0 / 24000.0) : model.sourceDuration(role),
                            fadeOutMS: role == "ka" ? 1 : 0))
                    }
                }
                HStack {
                    Text("淡入 ms")
                    TextField("淡入", value: Binding(get: { model.soundEdit(role).fadeInMS }, set: {
                        var edit = model.soundEdit(role); edit.fadeInMS = $0; model.setSoundEdit(role, edit)
                    }), format: .number).frame(width: 90)
                    Text("淡出 ms")
                    TextField("淡出", value: Binding(get: { model.soundEdit(role).fadeOutMS }, set: {
                        var edit = model.soundEdit(role); edit.fadeOutMS = $0; model.setSoundEdit(role, edit)
                    }), format: .number).frame(width: 90)
                    Text("源长度 \(String(format: "%.2f", model.sourceDuration(role) * 1000)) ms").font(.caption).foregroundStyle(.secondary)
                }
            }.textFieldStyle(.roundedBorder).padding(.top, 8)
        }.font(.callout)
    }
}

struct SoundWaveform: View {
    let url: URL?
    let start: Double
    let end: Double
    let duration: Double
    @State private var peaks: [Double] = []
    var body: some View {
        Canvas { context, size in
            let scale = duration > 0 ? size.width / duration : 0
            let left = max(0, min(size.width, (start.isFinite ? start : 0) * scale))
            let right = max(left, min(size.width, (end.isFinite ? end : 0) * scale))
            context.fill(Path(CGRect(x: left, y: 0, width: right - left, height: size.height)), with: .color(.accentColor.opacity(0.12)))
            var path = Path()
            for (index, value) in peaks.enumerated() {
                let x = size.width * Double(index) / Double(max(1, peaks.count - 1))
                let half = max(0.5, value * size.height * 0.46)
                path.move(to: CGPoint(x: x, y: size.height / 2 - half))
                path.addLine(to: CGPoint(x: x, y: size.height / 2 + half))
            }
            context.stroke(path, with: .color(.accentColor), lineWidth: 1)
        }.background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 5))
        .task(id: url?.path) {
            guard let url else { peaks = []; return }
            let result = await Task.detached { () -> [Double] in
                do {
                    let attrs = try url.resourceValues(forKeys: [.fileSizeKey])
                    guard let bytes = attrs.fileSize, bytes <= 16 * 1024 * 1024 else { return [] }
                    let file = try AVAudioFile(forReading: url, commonFormat: .pcmFormatFloat32, interleaved: false)
                    guard file.length > 0, file.length <= 1_920_000, file.processingFormat.channelCount <= 2,
                          let buffer = AVAudioPCMBuffer(pcmFormat: file.processingFormat, frameCapacity: AVAudioFrameCount(file.length)) else { return [] }
                    try file.read(into: buffer)
                    guard let channels = buffer.floatChannelData else { return [] }
                    var result = [Double](repeating: 0, count: 320)
                    for index in 0..<Int(buffer.frameLength) {
                        let bin = min(319, index * 320 / max(1, Int(buffer.frameLength)))
                        for channel in 0..<Int(buffer.format.channelCount) {
                            let sample = abs(Double(channels[channel][index]))
                            if sample.isFinite { result[bin] = max(result[bin], min(1, sample)) }
                        }
                    }
                    return result
                } catch { return [] }
            }.value
            guard !Task.isCancelled else { return }
            peaks = result
        }
    }
}

struct ApplicationConfirmationSheet: View {
    let review: ApplicationReview
    let cancel: () -> Void
    let confirm: (Bool, Bool, Bool) -> Void
    @State private var backupConfirmed = false
    @State private var nonbootRiskConfirmed = false
    @State private var personalRiskConfirmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("\(review.displayName) · 每次应用前确认").font(.title2.bold())
            Text("继续后将启动真实相机操作").font(.headline).foregroundStyle(.orange)
            Text("本次\(review.displayName)会在核对机身、完整备份和当前改动范围后写入。操作可能导致相机无法启动／变砖；软件检查不能消除风险。请逐项确认后再继续。")
                .font(.callout).foregroundStyle(.secondary)
            Text(review.backupSummary).font(.caption).foregroundStyle(.secondary)
            Divider()
            Toggle("我已完成并校验本次备份", isOn: $backupConfirmed)
            Toggle("我知道应用可能导致相机无法启动或变砖", isOn: $nonbootRiskConfirmed)
            Toggle("我已了解并愿意自行承担全部使用风险", isOn: $personalRiskConfirmed)
            Text("以上确认每次重新填写，不保存到偏好或项目；上次校验状态不会替代本次确认。")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("取消") { cancel() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("确认风险并开始本次操作…") { confirm(backupConfirmed, nonbootRiskConfirmed, personalRiskConfirmed) }
                    .buttonStyle(.borderedProminent)
                    .disabled(!backupConfirmed || !nonbootRiskConfirmed || !personalRiskConfirmed)
            }
        }.padding(26).frame(width: 590)
    }
}

struct BitmapPreview: View {
    var url: URL?
    var body: some View {
        Group {
            if let url, let image = NSImage(contentsOf: url) {
                Image(nsImage: image).resizable().interpolation(.none).scaledToFit()
            } else { Image(systemName: "photo").foregroundStyle(.secondary) }
        }.background(Color(white: 0.2), in: RoundedRectangle(cornerRadius: 5))
    }
}

@main struct A7IVToolbox: App {
    @NSApplicationDelegateAdaptor(ToolboxAppDelegate.self) private var appDelegate
    var body: some Scene {
        WindowGroup(ProductIdentity.title) { ProductView() }.defaultSize(width: 1120, height: 850)
    }
}
