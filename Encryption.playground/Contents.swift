import Foundation

let text = "something to encrypt"
let key = "$B&E)H@McQfTjWnZ"
let iv = "2RfAbNic!@NooR15"

/*:
 ## AES GCM
 
 Recommended by Apple
 
 - [More info](https://getstream.io/blog/ios-cryptokit-framework-chat/)
*/
/*:
 ### Data
*/
do {
    let data = Data(text.utf8)
    let keyData = Data(key.utf8)
    let aes = AESCrypt.GCM(key: keyData)
    let encrypted = try aes.encrypt(data)
    let decrypted = try aes.decrypt(encrypted)
    
    encrypted.base64EncodedString()
    String(data: decrypted, encoding: .utf8)
} catch {
    print(error)
}
/*:
 ### String
*/
do {
    let aes = AESCrypt.GCM(key: key)
    let encrypted = try aes.encrypt(text)
    _ = try aes.decrypt(encrypted)
} catch {
    print(error)
}
/*:
 ## AES CBC
 
 [More info](https://stackoverflow.com/a/37681510)
*/
/*:
 ### Data
*/
do {
    let data = Data(text.utf8)
    let keyData = Data(key.utf8)
    let aes = try AESCrypt.CBC(key: keyData)
    let encrypted = try aes.encrypt(data)
    let decrypted = try aes.decrypt(encrypted)
    
    encrypted.base64EncodedString()
    String(data: decrypted, encoding: .utf8)
} catch {
    print(error)
}
/*:
 ### String
*/
do {
    let aes = try AESCrypt.CBC(key: key)
    let encrypted = try aes.encrypt(text)
    _ = try aes.decrypt(encrypted)
} catch {
    print(error)
}
/*:
 ### Data with iv
*/

import CommonCrypto

do {
    let data = Data(text.utf8)
    let keyData = Data(key.utf8)
    let ivData = Data(iv.utf8)
    let aes = try AESCrypt.CBC(key: keyData)
    let encrypted = try aes.encrypt(data: data, ivData: ivData)
    let decrypted = try aes.decrypt(data: encrypted, ivData: ivData)
    
    encrypted.base64EncodedString()
    String(data: decrypted, encoding: .utf8)
} catch {
    print(error)
}
/*:
 ### String with iv
*/
do {
    let aes = try AESCrypt.CBC(key: key)
    let encrypted = try aes.encrypt(text: text, iv: iv)
    _ = try aes.decrypt(text: encrypted, iv: iv)
} catch {
    print(error)
}
