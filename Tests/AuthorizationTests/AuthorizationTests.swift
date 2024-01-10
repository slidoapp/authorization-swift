    import XCTest
    @testable import Authorization

    final class AuthorizationTests: XCTestCase {
        func testExecuteWithPrivileges_implicitAuthorization() throws {
            throw XCTSkip("user required")

            let fh = try Authorization.executeWithPrivileges(pathToTool: "/bin/ls", arguments: ["/"]).get()
            print(String(bytes: fh.readDataToEndOfFile(), encoding: .utf8)!)
        }
        
        func testExecuteWithPrivileges_explicitAuthorization() throws {
            throw XCTSkip("user required")
            
            let authorization = try Authorization.authorize(pathsToTools: ["/bin/ls"]).get()
            let fh = try Authorization.executeWithPrivileges(authorization: authorization, pathToTool: "/bin/ls", arguments: ["/"]).get()
            print(String(bytes: fh.readDataToEndOfFile(), encoding: .utf8)!)
        }
        
        func testDeprecatedExecuteWithPrivileges() throws {
            throw XCTSkip("user required")

            let fh = try Authorization.executeWithPrivileges("/bin/ls /").get()
            print(String(bytes: fh.readDataToEndOfFile(), encoding: .utf8)!)
        }
        
        func testAuthorizeWithCustomPrompt() throws {
            throw XCTSkip("user required")

            let authorization = try Authorization.authorize(pathsToTools: ["/bin/ls"], prompt: "Custom prompt for testing.").get()
            AuthorizationFree(authorization, [.destroyRights])
        }
    }
