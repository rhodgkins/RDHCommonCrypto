//
//  CryptorTests.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 15/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import XCTest
import UIKit

import RDHCommonCrypto

let Key: NSData! = Cryptor.randomDataWithLength(kCCKeySizeAES256)
let PlainTextInputData: NSData! = Cryptor.randomDataWithLength(997)

class CryptorTests: XCTestCase {
    
    // MARK: - Cryptor: encryption
    
    func testCryptorEncryptionWithEmptyKeyAndEmptyData() {

        // Without IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, NSData(), NSData(), self.name)
        // With IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), NSData(), NSData(), "\(self.name) with IV")
    }
    
    func testCryptorEncryptionWithKeyAndEmptyData() {
        
        // Without IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, Key, NSData(), self.name)
        // With IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), Key, NSData(), "\(self.name) with IV")
    }
    
    func testCryptorEncryptionWithEmptyKeyAndData() {
        
        // Without IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, NSData(), PlainTextInputData, self.name)
        // With IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), NSData(), PlainTextInputData, "\(self.name) with IV")
    }

    func testCryptorEncryptionWithKeyAndData() {
        
        // Without IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, Key, PlainTextInputData, self.name)
        // With IV
        cryptorTestsEncrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), Key, PlainTextInputData, "\(self.name) with IV")
    }
    
    func testAllEncryptions() {
        
        let algorithms = ["AES with 128 key size" : (kCCAlgorithmAES, kCCKeySizeAES128, kCCBlockSizeAES128),
            "AES with 192 key size" : (kCCAlgorithmAES, kCCKeySizeAES192, kCCBlockSizeAES128),
            "AES with 256 key size" : (kCCAlgorithmAES, kCCKeySizeAES256, kCCBlockSizeAES128),
            "AES128 with 128 key size" : (kCCAlgorithmAES128, kCCKeySizeAES128, kCCBlockSizeAES128),
            "DES with standard key size" : (kCCAlgorithmDES, kCCKeySizeDES, kCCBlockSizeDES),
            "3DES with standard key size" : (kCCAlgorithm3DES, kCCKeySize3DES, kCCBlockSize3DES),
            "CAST with random key size" : (kCCAlgorithmCAST, kCCKeySizeMinCAST + (random() % (kCCKeySizeMaxCAST - kCCKeySizeMinCAST)), kCCBlockSizeCAST),
            "Blowfish with random key size" : (kCCAlgorithmBlowfish, kCCKeySizeMinBlowfish + (random() % (kCCKeySizeMaxBlowfish - kCCKeySizeMinBlowfish)), kCCBlockSizeBlowfish),
            "RC2 with random key size" : (kCCAlgorithmRC2, kCCKeySizeMinRC2 + (random() % (kCCKeySizeMaxRC2 - kCCKeySizeMinRC2)), kCCBlockSizeRC2),
            "RC4 with random key size" : (kCCAlgorithmRC4, kCCKeySizeMinRC4 + (random() % (kCCKeySizeMaxRC4 - kCCKeySizeMinRC4)), 1)]
        
        let options = ["no options" : 0,
            "PKCS7 padding" : kCCOptionPKCS7Padding,
            "ECB" : kCCOptionECBMode,
            "PKCS7 padding and ECB" : kCCOptionPKCS7Padding | kCCOptionECBMode]
        
        var count = 0
        for (algKey, (alg, keySize, blockSize)) in algorithms {
            
            for (optKey, opt) in options {
                
                var dataInLength = 997 + (random() % 997)
                
                if ((opt & kCCOptionPKCS7Padding) == 0) {
                    
                    func align(size: Int) -> Int {
                        if (size % blockSize) == 0 {
                            return size
                        } else {
                            let numberOfBlocks = size / blockSize
                            return (numberOfBlocks + 1) * blockSize
                        }
                    }
                    
                    NSLog("Re-adjusting input data to block size: \(dataInLength) -> \(align(dataInLength))")
                    dataInLength = align(dataInLength)
                }
                
                let key: NSData! = Cryptor.randomDataWithLength(keySize)
                let inData: NSData! = Cryptor.randomDataWithLength(dataInLength)
                let iv = CCAlgorithm(alg).randomIV()
                
                let message = "Testing \(algKey) of \(key.length) with \(optKey)"
                NSLog(message)
                
                // Without IV
                let noIVMessage = "\(message) and no IV"
                let noIVResult = cryptorTestsEncrypt(alg, opt, nil, key, inData, noIVMessage)
                XCTAssert(noIVResult, noIVMessage)
                count++
                
                if let unwrappedIV = iv {
                    // With IV
                    let IVMessage = "\(message) and IV of length \(unwrappedIV.length)"
                    let IVResult = cryptorTestsEncrypt(alg, opt, unwrappedIV, key, inData, IVMessage)
                    XCTAssert(IVResult, IVMessage)
                        count++
                }
            }
        }
        
        NSLog("\(count) different encryption combinations run")
    }
    
    // MARK: -
    
    func cryptorTestsEncrypt(algorithm: Int, _ options: Int, _ iv: NSData?, _ key: NSData, _ plainTextData: NSData, _ message: String = "") -> Bool {
        
        let ccAlgorithm = CCAlgorithm(algorithm)
        let ccOptions = CCOptions(options)
        
        let alg = RDHAlgorithm.fromRaw(ccAlgorithm)!
        let opts = [Option(Int(ccOptions))]
        
        // Swift API
        let (actualDataOut, actualError) = Cryptor.encrypt(alg, usingOptions: opts, withKey: key, initialisationVector: iv, dataIn: plainTextData)
        
        
        // Original CommonCrypto API
        let (expectedStatus, expectedOutData) = cryptorData(kCCEncrypt, ccAlgorithm, ccOptions, key, iv, plainTextData)
    
        var result = true
        
        // Check
        if (expectedStatus == CCStatus(kCCSuccess)) {
            // Data should be equal, error should be nil
            
            if let unwrappedActualDataOut = actualDataOut {
                XCTAssertEqual(unwrappedActualDataOut.length, expectedOutData!.length, "Encrypted data is incorrect length: \(message)")
                result &= unwrappedActualDataOut.length == expectedOutData!.length
                
                // Try decrypting the cryptor encrypted data
                let (decryptStatus, decryptedActualData) = cryptorData(kCCDecrypt, ccAlgorithm, ccOptions, key, iv, unwrappedActualDataOut)
                
                if (decryptStatus == CCStatus(kCCSuccess)) {
                    XCTAssertEqual(decryptedActualData!.length, plainTextData.length, "Decrypting the encrytped data did not yeild the same data length: \(message)")
                    XCTAssertTrue(decryptedActualData! == plainTextData, "Decrypting the encrytped data did not yeild the same data: \(message)")
                    result &= decryptedActualData! == plainTextData
                } else {
                    XCTFail("Failed to decrypted the encrypted data: \(message)")
                    result &= false
                }
                
            } else {
                XCTAssertNotNil(actualDataOut, "Data should not be nil: \(message)")
                result &= actualDataOut != nil
            }
            XCTAssertNil(actualError, "Error should be nil - \(actualError): \(message)")
            result &= actualError == nil
            
        } else {
            // Data should be nil, error should be set
            
            XCTAssertNil(actualDataOut, "Data out not nil: \(message)")
            result &= actualDataOut == nil
            if let unwrappedActualError = actualError {
                XCTAssertEqual(unwrappedActualError.code, Int(expectedStatus), "Status is incorrect: \(message)")
                result &= unwrappedActualError.code == Int(expectedStatus)
            } else {
                XCTAssertNotNil(actualError, "Error should not be nil: \(message)")
                result &= actualError != nil
            }
        }
        
        return result
    }
    
    // MARK: - Cryptor: decryption
    
    func testCryptorDecryptionWithEmptyKeyAndEmptyData() {
        
        // Without IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, NSData(), NSData(), self.name)
        // With IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), NSData(), NSData(), "\(self.name) with IV")
    }
    
    func testCryptorDecryptionWithKeyAndEmptyData() {
        
        // Without IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, Key, NSData(), self.name)
        // With IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), Key, NSData(), "\(self.name) with IV")
    }
    
    func testCryptorDecryptionWithEmptyKeyAndData() {
        
        // Without IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, nil, NSData(), PlainTextInputData, self.name)
        // With IV
        cryptorTestsDecrypt(kCCAlgorithmAES, kCCOptionPKCS7Padding, Cryptor.randomDataWithLength(kCCBlockSizeAES128), NSData(), PlainTextInputData, "\(self.name) with IV")
    }
    
    func testCryptorDecryptionWithKeyAndData() {
        
        let algorithm = kCCAlgorithmAES
        let options = kCCOptionPKCS7Padding
        
        let iv = Cryptor.randomDataWithLength(kCCBlockSizeAES128)
        let key = Cryptor.randomDataWithLength(kCCKeySizeAES256)!
        let plainTextData = PlainTextInputData
        
        // Without IV
        cryptorDecryption(algorithm, options, key, nil, plainTextData, message: self.name)
        // With IV
        cryptorDecryption(algorithm, options, key, nil, plainTextData, message: "\(self.name) with IV")
    }
    
    func testAllDecryptions() {
        
        let algorithms = ["AES with 128 key size" : (kCCAlgorithmAES, kCCKeySizeAES128, kCCBlockSizeAES128),
            "AES with 192 key size" : (kCCAlgorithmAES, kCCKeySizeAES192, kCCBlockSizeAES128),
            "AES with 256 key size" : (kCCAlgorithmAES, kCCKeySizeAES256, kCCBlockSizeAES128),
            "AES128 with 128 key size" : (kCCAlgorithmAES128, kCCKeySizeAES128, kCCBlockSizeAES128),
            "DES with standard key size" : (kCCAlgorithmDES, kCCKeySizeDES, kCCBlockSizeDES),
            "3DES with standard key size" : (kCCAlgorithm3DES, kCCKeySize3DES, kCCBlockSize3DES),
            "CAST with random key size" : (kCCAlgorithmCAST, kCCKeySizeMinCAST + (random() % (kCCKeySizeMaxCAST - kCCKeySizeMinCAST)), kCCBlockSizeCAST),
            "Blowfish with random key size" : (kCCAlgorithmBlowfish, kCCKeySizeMinBlowfish + (random() % (kCCKeySizeMaxBlowfish - kCCKeySizeMinBlowfish)), kCCBlockSizeBlowfish),
            "RC2 with random key size" : (kCCAlgorithmRC2, kCCKeySizeMinRC2 + (random() % (kCCKeySizeMaxRC2 - kCCKeySizeMinRC2)), kCCBlockSizeRC2),
            "RC4 with random key size" : (kCCAlgorithmRC4, kCCKeySizeMinRC4 + (random() % (kCCKeySizeMaxRC4 - kCCKeySizeMinRC4)), 1)]
        
        let options = ["no options" : 0,
            "PKCS7 padding" : kCCOptionPKCS7Padding,
            "ECB" : kCCOptionECBMode,
            "PKCS7 padding and ECB" : kCCOptionPKCS7Padding | kCCOptionECBMode]
        
        var count = 0
        for (algKey, (alg, keySize, blockSize)) in algorithms {
            
            for (optKey, opt) in options {
                
                var dataInLength = 997 + (random() % 997)
                
                if ((opt & kCCOptionPKCS7Padding) == 0) {
                    
                    func align(size: Int) -> Int {
                        if (size % blockSize) == 0 {
                            return size
                        } else {
                            let numberOfBlocks = size / blockSize
                            return (numberOfBlocks + 1) * blockSize
                        }
                    }
                    
                    NSLog("Re-adjusting input data to block size: \(dataInLength) -> \(align(dataInLength))")
                    dataInLength = align(dataInLength)
                }
                
                let key: NSData! = Cryptor.randomDataWithLength(keySize)
                let inData: NSData! = Cryptor.randomDataWithLength(dataInLength)
                let iv = CCAlgorithm(alg).randomIV()
                
                let message = "Testing decryption \(algKey) of \(key.length) with \(optKey)"
                NSLog(message)
                
                // Without IV
                let noIVMessage = "\(message) and no IV"
                let noIVResult = cryptorDecryption(alg, opt, key, nil, inData, message: self.name)
                XCTAssert(noIVResult, noIVMessage)
                count++
                
                if let unwrappedIV = iv {
                    // With IV
                    let IVMessage = "\(message) and IV of length \(unwrappedIV.length)"
                    let IVResult = cryptorDecryption(alg, opt, key, nil, inData, message: "\(self.name) with IV")
                    XCTAssert(IVResult, IVMessage)
                    count++
                }
            }
        }
        
        NSLog("\(count) different decryption combinations run")
    }
    
    func cryptorDecryption(algorithm: Int, _ options: Int, _ key: NSData, _ iv: NSData?, _ plainTextData: NSData, message: String) -> Bool {
        
        let cipherTextData: NSData! = cryptorData(kCCEncrypt, CCAlgorithm(algorithm), CCOptions(options), key, iv, plainTextData).dataOut
        
        return cryptorTestsDecrypt(algorithm, options, iv, key, cipherTextData, message)
    }
    
    // MARK: -
    
    func cryptorTestsDecrypt(algorithm: Int, _ options: Int, _ iv: NSData?, _ key: NSData, _ cipherTextData: NSData, _ message: String = "") -> Bool {
    
        let ccAlgorithm = CCAlgorithm(algorithm)
        let ccOptions = CCOptions(options)
        
        let alg = RDHAlgorithm.fromRaw(ccAlgorithm)!
        let opts = [Option(Int(ccOptions))]
        
        // Swift API
        let (actualDataOut, actualError) = Cryptor.decrypt(alg, usingOptions: opts, withKey: key, initialisationVector: iv, dataIn: cipherTextData)
        
        
        // Original CommonCrypto API
        let (expectedStatus, expectedOutData) = cryptorData(kCCDecrypt, ccAlgorithm, ccOptions, key, iv, cipherTextData)
        
        var result = true
        
        // Check
        if (expectedStatus == CCStatus(kCCSuccess)) {
            // Data should be equal, error should be nil
            
            if let unwrappedActualDataOut = actualDataOut {
                XCTAssertEqual(unwrappedActualDataOut.length, expectedOutData!.length, "Encrypted data length is incorrect: \(message)")

                XCTAssertTrue(unwrappedActualDataOut == expectedOutData!, "Encrypted data is incorrect: \(message)")
                result &= unwrappedActualDataOut == expectedOutData!
            } else {
                XCTAssertNotNil(actualDataOut, "Data should not be nil: \(message)")
                result &= actualDataOut != nil
            }
            XCTAssertNil(actualError, "Error should be nil - \(actualError): \(message)")
            result &= actualError == nil
            
        } else {
            // Data should be nil, error should be set
            
            XCTAssertNil(actualDataOut, "Data out not nil: \(message)")
            result &= actualDataOut == nil
            if let unwrappedActualError = actualError {
                XCTAssertEqual(unwrappedActualError.code, Int(expectedStatus), "Status is incorrect: \(message)")
                result &= unwrappedActualError.code == Int(expectedStatus)
            } else {
                XCTAssertNotNil(actualError, "Error should not be nil: \(message)")
                result &= actualError != nil
            }
        }
        
        return result
    }
}

func cryptorData(operation: Int, algorithm: CCAlgorithm, options: CCOptions, key: NSData, iv: NSData?, dataIn: NSData) -> (status: CCStatus, dataOut: NSData?) {
    
    let outDataLength = dataIn.length + 256 // 256 should be bigger than the largest block size
    var outData: NSMutableData? = NSMutableData(length: outDataLength)
    var dataOutMoved: UInt = 0
    var bytesOut = outData!.mutableBytes
    
    let status = CCCrypt(CCOperation(operation), algorithm, options, key.bytes, UInt(key.length), iv == nil ? nil : iv!.bytes, dataIn.bytes, UInt(dataIn.length), bytesOut, UInt(outDataLength), &dataOutMoved)
    
    if (status == CCStatus(kCCSuccess)) {
        // Cut data to correct length
        outData!.length = Int(dataOutMoved)
        return (status, NSData(data: outData!))
    } else {
        return (status, nil)
    }
}
