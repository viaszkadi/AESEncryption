import Foundation
import CommonCrypto

public extension AESCrypt {
    
    struct CBC {
        private let key: Data
        private let ivSize = kCCBlockSizeAES128
        private let options = CCOptions(kCCOptionPKCS7Padding)
        private let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        
        public init(key: Data) throws {
            if !validKeyLengths.contains(key.count) {
                throw AESCrypt.Error.invalidKeySize
            }
            
            self.key = key
        }
        
        public init(key: String) throws {
            let keyData = Data(key.utf8)
            try self.init(key: keyData)
        }
    }
}

private extension AESCrypt.CBC {
    
    func generateRandomIV(for data: inout Data) throws {
        try data.withUnsafeMutableBytes { dataBytes in
            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw AESCrypt.Error.ivGenerationFailed
            }
            
            let status = SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, dataBytesBaseAddress)
            
            guard status == errSecSuccess else {
                throw AESCrypt.Error.ivGenerationFailed
            }
        }
    }
}

public extension AESCrypt.CBC {
    
    func encrypt(_ data: Data) throws -> Data {
        let bufferSize: Int = ivSize + data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        try generateRandomIV(for: &buffer)
        
        var numberBytesEncrypted: Int = 0
        
        do {
            try key.withUnsafeBytes { keyBytes in
                try data.withUnsafeBytes { dataBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        guard
                            let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataBytesBaseAddress = dataBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress
                        else {
                            throw AESCrypt.Error.encryptionFailed
                        }
                        
                        let cryptStatus = CCCrypt(              // Stateless, one-shot encrypt operation
                            CCOperation(kCCEncrypt),            // op: CCOperation
                            CCAlgorithm(kCCAlgorithmAES),       // alg: CCAlgorithm
                            options,                            // options: CCOptions
                            keyBytesBaseAddress,                // key: the "password"
                            key.count,                          // keyLength: the "password" size
                            bufferBytesBaseAddress,             // iv: Initialization Vector
                            dataBytesBaseAddress,               // dataIn: Data to encrypt bytes
                            dataBytes.count,                    // dataInLength: Data to encrypt size
                            bufferBytesBaseAddress + ivSize,    // dataOut: encrypted Data buffer
                            bufferSize,                         // dataOutAvailable: encrypted Data buffer size
                            &numberBytesEncrypted               // dataOutMoved: the number of bytes written
                        )
                        
                        guard cryptStatus == kCCSuccess else {
                            throw AESCrypt.Error.encryptionFailed
                        }
                    }
                }
            }
            
        } catch {
            throw AESCrypt.Error.encryptionFailed
        }
        
        let encryptedData: Data = buffer[..<(numberBytesEncrypted + ivSize)]
        return encryptedData
    }
    
    func decrypt(_ data: Data) throws -> Data {
        let bufferSize: Int = data.count - ivSize
        var buffer = Data(count: bufferSize)
        
        var numberBytesDecrypted: Int = 0
        
        do {
            try key.withUnsafeBytes { keyBytes in
                try data.withUnsafeBytes { dataBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        guard
                            let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataToDecryptBytesBaseAddress = dataBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress
                        else {
                            throw AESCrypt.Error.encryptionFailed
                        }
                        
                        let status = CCCrypt(                          // Stateless, one-shot encrypt operation
                            CCOperation(kCCDecrypt),                   // op: CCOperation
                            CCAlgorithm(kCCAlgorithmAES128),           // alg: CCAlgorithm
                            options,                                   // options: CCOptions
                            keyBytesBaseAddress,                       // key: the "password"
                            key.count,                                 // keyLength: the "password" size
                            dataToDecryptBytesBaseAddress,             // iv: Initialization Vector
                            dataToDecryptBytesBaseAddress + ivSize,    // dataIn: Data to decrypt bytes
                            bufferSize,                                // dataInLength: Data to decrypt size
                            bufferBytesBaseAddress,                    // dataOut: decrypted Data buffer
                            bufferSize,                                // dataOutAvailable: decrypted Data buffer size
                            &numberBytesDecrypted                      // dataOutMoved: the number of bytes written
                        )
                        
                        guard status == kCCSuccess else {
                            throw AESCrypt.Error.decryptionFailed
                        }
                    }
                }
            }
        } catch {
            throw AESCrypt.Error.decryptionFailed
        }
        
        let decryptedData: Data = buffer[..<numberBytesDecrypted]
        return decryptedData
    }
}

public extension AESCrypt.CBC {

    func encrypt(_ text: String) throws -> String {
        let data = Data(text.utf8)
        let encrypted = try encrypt(data)

        return encrypted.base64EncodedString()
    }

    func decrypt(_ text: String) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw AESCrypt.Error.decryptionFailed
        }

        let decrypted = try decrypt(data)

        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw AESCrypt.Error.decryptionFailed
        }

        return result
    }
}

private extension AESCrypt.CBC {
    
    func crypt(operation: CCOperation, data: Data, ivData: Data) throws -> Data {
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)

        let keyLength = size_t(kCCKeySizeAES128)
        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                ivData.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                        CCCrypt(CCOperation(operation),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress,
                                keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress,
                                data.count,
                                cryptBytes.baseAddress,
                                cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }

        if cryptStatus == kCCSuccess {
            cryptData.removeSubrange(numBytesEncrypted ..< cryptData.count)
        } else {
            throw AESCrypt.Error.decryptionFailed
        }

        return cryptData
    }
}

public extension AESCrypt.CBC {
    
    func encrypt(data: Data, ivData: Data) throws -> Data {
        try crypt(operation: CCOperation(kCCEncrypt), data: data, ivData: ivData)
    }
    
    func decrypt(data: Data, ivData: Data) throws -> Data {
        try crypt(operation: CCOperation(kCCDecrypt), data: data, ivData: ivData)
    }
}

public extension AESCrypt.CBC {
    
    func encrypt(text: String, iv: String) throws -> String {
        let data = Data(text.utf8)
        let ivData = Data(iv.utf8)
        let encrypted = try encrypt(data: data, ivData: ivData)
        
        return encrypted.base64EncodedString()
    }
    
    func decrypt(text: String, iv: String) throws -> String {
        let ivData = Data(iv.utf8)

        guard let data = Data(base64Encoded: text) else {
            throw AESCrypt.Error.decryptionFailed
        }

        let decrypted = try decrypt(data: data, ivData: ivData)

        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw AESCrypt.Error.decryptionFailed
        }

        return result
    }
}
