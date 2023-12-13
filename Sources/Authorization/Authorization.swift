import Foundation
import Swift

// https://github.com/sveinbjornt/STPrivilegedTask/blob/master/STPrivilegedTask.m
// https://github.com/gui-dos/Guigna/blob/9fdd75ca0337c8081e2a2727960389c7dbf8d694/Legacy/Guigna-Swift/Guigna/GAgent.swift#L42-L80

public struct Authorization {
    
    public enum Error: Swift.Error {
        case create(OSStatus)
        case copyRights(OSStatus)
        case exec(OSStatus)
    }

    /// Runs an executable tool with root privileges.
    /// - Parameters:
    ///   - pathToTool: The full POSIX pathname of the tool to execute.
    ///   - arguments: Array of strings to send to the tool.
    /// - Returns: A file handle to the output of the command or an error.
    public static func executeWithPrivileges(
        pathToTool: String,
        arguments: [String] = []
    ) -> Result<FileHandle, Error> {
        
        let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
        var fn: @convention(c) (
            AuthorizationRef,
            UnsafePointer<CChar>,  // path
            AuthorizationFlags,
            UnsafePointer<UnsafePointer<CChar>?>,  // args
            UnsafeMutablePointer<UnsafeMutablePointer<FILE>>?
        ) -> OSStatus
        fn = unsafeBitCast(
            dlsym(RTLD_DEFAULT, "AuthorizationExecuteWithPrivileges"),
            to: type(of: fn)
        )
        
        var authorizationRef: AuthorizationRef? = nil
        var err = AuthorizationCreate(nil, nil, [], &authorizationRef)
        guard err == errAuthorizationSuccess else {
            return .failure(.create(err))
        }
        defer { AuthorizationFree(authorizationRef!, [.destroyRights]) }
        
        var pathCString = pathToTool.cString(using: .utf8)!
        let name = kAuthorizationRightExecute.cString(using: .utf8)!
        
        var items: AuthorizationItem = name.withUnsafeBufferPointer { nameBuf in
            pathCString.withUnsafeBufferPointer { pathBuf in
                let pathPtr =
                    UnsafeMutableRawPointer(mutating: pathBuf.baseAddress!)
                return AuthorizationItem(
                    name: nameBuf.baseAddress!,
                    valueLength: pathCString.count,
                    value: pathPtr,
                    flags: 0
                )
            }
        }
        
        var rights: AuthorizationRights =
            withUnsafeMutablePointer(to: &items) { items in
                return AuthorizationRights(count: 1, items: items)
            }
        
        let flags: AuthorizationFlags = [
            .interactionAllowed,
            .preAuthorize,
            .extendRights,
        ]
        
        err = AuthorizationCopyRights(
            authorizationRef!,
            &rights,
            nil,
            flags,
            nil
        )
        guard err == errAuthorizationSuccess else {
            return .failure(.copyRights(err))
        }
        
        let argsCString = arguments.map { $0.cString(using: .utf8)! }
        var argsArgvStyle = Array<UnsafePointer<CChar>?>(
            repeating: nil,
            count: argsCString.count + 1
        )
        for (idx, arg) in argsCString.enumerated() {
            argsArgvStyle[idx] = UnsafePointer<CChar>?(arg)
        }
        
        var file = FILE()
        let fh: FileHandle?
        
        (err, fh) = withUnsafeMutablePointer(to: &file) { file in
            var pipe = file
            let err = fn(authorizationRef!, &pathCString, [], &argsArgvStyle, &pipe)
            guard err == errAuthorizationSuccess else {
                return (err, nil)
            }
            let fh = FileHandle(
                fileDescriptor: fileno(pipe),
                closeOnDealloc: true
            )
            return (err, fh)
        }
        guard err == errAuthorizationSuccess else {
            return .failure(.exec(err))
        }
        return .success(fh!)
    }
    
    @available(*, deprecated, message: "Use executeWithPrivileges(pathToTool:arguments:) instead.")
    public static func executeWithPrivileges(
        _ command: String
    ) -> Result<FileHandle, Error> {
        var components = command.components(separatedBy: " ")
        let path = components.remove(at: 0)
        return Self.executeWithPrivileges(pathToTool: path, arguments: components)
    }
}
