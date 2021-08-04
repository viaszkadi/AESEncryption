import Foundation

public enum AESCrypt {
    
}

public extension AESCrypt {
    
    enum Error: Swift.Error {
        case invalidKeySize
        case ivGenerationFailed
        case encryptionFailed
        case decryptionFailed
    }
}
