import Foundation
import LocalAuthentication

/// Resolves the device's biometric modality so user-facing strings match the hardware.
///
/// SE Pass targets iOS 16+, which includes Touch ID devices (notably the iPhone SE 2nd/
/// 3rd gen). Our Secure Enclave gate uses `.biometryCurrentSet` + LocalAuthentication,
/// which already works with whichever biometric the device has — only the *wording*
/// needs to adapt so we don't say "Face ID" while someone presses a fingerprint sensor.
///
/// Note: `LAContext.biometryType` is only populated after a `canEvaluatePolicy(...)`
/// call, so we probe a throwaway context. We deliberately don't reference `.opticID`
/// (Vision Pro, iOS 17+) by name to avoid an availability guard on our iOS 16 target;
/// it — and `.none` — fall through to the generic label. In practice, on the iPhones
/// this app runs on, the result is always Face ID or Touch ID.
enum Biometry {
    private static var type: LABiometryType {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType
    }

    /// Human-readable name for prompts and labels, e.g. "Face ID" or "Touch ID".
    static var label: String {
        switch type {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default: return "biometrics"      // .none, or .opticID (Vision Pro only)
        }
    }

    /// Matching SF Symbol for the modality.
    static var iconName: String {
        switch type {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        default: return "lock.fill"
        }
    }
}
