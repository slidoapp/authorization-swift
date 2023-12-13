    import XCTest
    @testable import Authorization

    final class AuthorizationTests: XCTestCase {
        func testExecuteWithPrivileges() throws {
            throw XCTSkip("user required")

            let fh = try Authorization.executeWithPrivileges(pathToTool: "/bin/ls", arguments: ["/"]).get()
            print(String(bytes: fh.readDataToEndOfFile(), encoding: .utf8)!)
        }
        
        func testDeprecatedExecuteWithPrivileges() throws {
            throw XCTSkip("user required")

            let fh = try Authorization.executeWithPrivileges("/bin/ls /").get()
            print(String(bytes: fh.readDataToEndOfFile(), encoding: .utf8)!)
        }
    }
