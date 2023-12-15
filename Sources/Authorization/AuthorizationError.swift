import Foundation

public enum AuthorizationError: Error, CustomStringConvertible {
    case create(OSStatus)
    case copyRights(OSStatus)
    case exec(OSStatus)
    
    public var description: String {
        switch self {
        case let .create(osStatus):
            return "Unable to create authorization. \(Self.describe(osStatus))"
        case let .copyRights(osStatus):
            return "Unable to authorize rights. \(Self.describe(osStatus))"
        case let .exec(osStatus):
            return "Unable to execute command. \(Self.describe(osStatus))"
        }
    }
    
    private static func describe(_ osStatus: OSStatus) -> String {
        SecCopyErrorMessageString(osStatus, nil) as String? ?? "Status code: \(osStatus)"
    }
}
