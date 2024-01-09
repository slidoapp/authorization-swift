import Foundation
import Swift

public struct Authorization {
    
    /// Creates an authorizartion allowing to use specified executabale tools with admin privileges.
    /// - Parameter pathsToTools: A set containing paths to tools for which we require authorization.
    /// - Parameter prompt: A custom prompt (text) displayed in the authorization dialog instead of the system one.
    /// - Returns: An opaque reference to an authorization object authorized to the specified tools or an error.
    public static func authorize(
        pathsToTools: Set<String>,
        prompt: String? = nil
    ) -> Result<AuthorizationRef, AuthorizationError> {
        var authorizationRef: AuthorizationRef? = nil
        var err = AuthorizationCreate(nil, nil, [], &authorizationRef)
        guard err == errAuthorizationSuccess else {
            return .failure(.create(err))
        }
        
        let pathsCString = pathsToTools.map { $0.cString(using: .utf8)! }
        let name = kAuthorizationRightExecute.cString(using: .utf8)!
        
        var items = pathsCString.map { path in
            name.withUnsafeBufferPointer { nameBuf in
                path.withUnsafeBufferPointer { pathBuf in
                    let pathPtr = UnsafeMutableRawPointer(mutating: pathBuf.baseAddress!)
                    return AuthorizationItem(
                        name: nameBuf.baseAddress!,
                        valueLength: path.count,
                        value: pathPtr,
                        flags: 0
                    )
                }
            }
        }
        
        let itemsCount = UInt32(items.count)
        var rights: AuthorizationRights =
            items.withUnsafeMutableBufferPointer { itemsBuf in
                return AuthorizationRights(count: itemsCount, items: itemsBuf.baseAddress)
            }
        
        let flags: AuthorizationFlags = [
            .interactionAllowed,
            .preAuthorize,
            .extendRights,
        ]
        
        if let prompt {
            let name = kAuthorizationEnvironmentPrompt.cString(using: .utf8)!
            let promptCString = prompt.cString(using: .utf8)!
            
            var promptItem = name.withUnsafeBufferPointer { nameBuf in
                promptCString.withUnsafeBufferPointer { promptBuf in
                    AuthorizationItem(
                        name: nameBuf.baseAddress!,
                        valueLength: promptCString.count,
                        value: UnsafeMutableRawPointer(mutating: promptBuf.baseAddress!),
                        flags: 0
                    )
                }
            }
            
            var environment = withUnsafeMutablePointer(to: &promptItem) { promptItemPtr in
                AuthorizationEnvironment(count: 1, items: promptItemPtr)
            }
            
            err = AuthorizationCopyRights(
                authorizationRef!,
                &rights,
                &environment,
                flags,
                nil
            )
        } else {
            err = AuthorizationCopyRights(
                authorizationRef!,
                &rights,
                nil,
                flags,
                nil
            )
        }
        
        guard err == errAuthorizationSuccess else {
            return .failure(.copyRights(err))
        }
        
        return .success(authorizationRef!)
    }

    /// Runs an executable tool with root privileges.
    /// - Parameters:
    ///   - authorization: An authorization reference referring to the authorization session. Pass NIL if you want use the implicit authorization.
    ///   - pathToTool: The full POSIX pathname of the tool to execute.
    ///   - arguments: Array of strings to send to the tool.
    /// - Returns: A file handle to the output of the command or an error.
    public static func executeWithPrivileges(
        authorization: AuthorizationRef? = nil,
        pathToTool: String,
        arguments: [String] = []
    ) -> Result<FileHandle, AuthorizationError> {
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
        
        var authorization = authorization
        let useImplicitAuthorization = authorization == nil
        
        if useImplicitAuthorization {
            switch Self.authorize(pathsToTools: [pathToTool]) {
            case .success(let implicitAuthorization):
                authorization = implicitAuthorization
            case .failure(let error):
                return .failure(error)
            }
        }
        
        defer {
            if useImplicitAuthorization {
                AuthorizationFree(authorization!, [.destroyRights])
            }
        }
        
        var pathCString = pathToTool.cString(using: .utf8)!
        let argsCString = arguments.map { $0.cString(using: .utf8)! }
        var argsArgvStyle = Array<UnsafePointer<CChar>?>(
            repeating: nil,
            count: argsCString.count + 1
        )
        for (idx, arg) in argsCString.enumerated() {
            argsArgvStyle[idx] = UnsafePointer<CChar>?(arg)
        }
        
        var err: OSStatus
        var file = FILE()
        let fh: FileHandle?
        
        (err, fh) = withUnsafeMutablePointer(to: &file) { file in
            var pipe = file
            let err = fn(authorization!, &pathCString, [], &argsArgvStyle, &pipe)
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
    ) -> Result<FileHandle, AuthorizationError> {
        var components = command.components(separatedBy: " ")
        let path = components.remove(at: 0)
        return Self.executeWithPrivileges(pathToTool: path, arguments: components)
    }
}
