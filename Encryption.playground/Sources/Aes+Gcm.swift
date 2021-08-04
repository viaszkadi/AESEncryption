import Foundation
import CryptoKit

public extension AESCrypt {
    
    struct GCM {
        private let key: Data
        
        public init(key: Data) {
            self.key = key
        }
        
        public init(key: String) {
            self.key = Data(key.utf8)
        }
    }
}

public extension AESCrypt.GCM {
    
    func encrypt(_ data: Data) throws -> Data {
        let sealedBox = try CryptoKit.AES.GCM.seal(data, using: .init(data: key))
        return sealedBox.combined!
    }
    
    func decrypt(_ data: Data) throws -> Data {
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: data)
        return try CryptoKit.AES.GCM.open(sealedBox, using: .init(data: key))
    }
}

public extension AESCrypt.GCM {
    
    func encrypt(_ text: String) throws -> String {
        let data = Data(text.utf8)
        return try encrypt(data).base64EncodedString()
    }
    
    func decrypt(_ text: String) throws -> String {
        let data = Data(base64Encoded: text)!
        let decryptedData = try decrypt(data)
        return String(data: decryptedData, encoding: .utf8)!
    }
}
