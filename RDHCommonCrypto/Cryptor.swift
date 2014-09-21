//
//  Cryptor.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 15/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation
import Security

/// Operations that an CCCryptor can perform.
public enum Operation : Int {
    /// Symmetric encryption.
    case Encrypt
    /// Symmetric decryption.
    case Decrypt
    
    private var cValue: CCOperation {
        switch (self) {
            case .Encrypt:
                return CCOperation(kCCEncrypt)
            case .Decrypt:
                return CCOperation(kCCDecrypt)
        }
    }
};

private extension CCAlgorithm
{
    /// @returns the block size for the algorithm
    private var blockSize: Int {
        switch(Int(self)) {
            case kCCAlgorithmAES:
                fallthrough
            case kCCAlgorithmAES128:
                return RDHBlockSizeAES128.value
            case kCCAlgorithmDES:
                return RDHBlockSizeDES.value
            case kCCAlgorithm3DES:
                return RDHBlockSizeTripleDES.value
            case kCCAlgorithmCAST:
                return RDHBlockSizeCAST.value
            case kCCAlgorithmRC2:
                return RDHBlockSizeRC2.value
            case kCCAlgorithmBlowfish:
                return RDHBlockSizeBlowfish.value
            case kCCAlgorithmRC4:
                // Stream ciphers have no block size
                return 0
            default:
                return 0
        }
    }
    
    private var contextSize: Int {
        switch(Int(self)) {
        case kCCAlgorithmAES:
            fallthrough
        case kCCAlgorithmAES128:
            return RDHContextSizeAES128.value
        case kCCAlgorithmDES:
            return RDHContextSizeDES.value
        case kCCAlgorithm3DES:
            return RDHContextSizeTripleDES.value
        case kCCAlgorithmCAST:
            return RDHContextSizeCAST.value
        case kCCAlgorithmRC4:
            return RDHContextSizeRC4.value
        case kCCAlgorithmRC2:
            return 128
        case kCCAlgorithmBlowfish:
            return 128
        default:
            return 0
        }
    }
}

private extension RDHAlgorithm
{
    /// @returns the block size for the algorithm
    private var blockSize: Int {
        return self.toRaw().blockSize
    }
    
    /// @returns the memory size needed to create the CryptorRef for the algorithm
    private var contextSize: Int {
        return self.toRaw().contextSize
    }
}

public extension CCAlgorithm
{
    public func randomIV() -> NSData? {
        if (self == CCAlgorithm(kCCAlgorithmRC4)) {
            // Stream cipher return nil
            return nil
        } else {
            return Cryptor.randomDataWithLength(self.blockSize)
        }
    }
}

public extension RDHAlgorithm
{
    public func randomIV() -> NSData? {
        return self.toRaw().randomIV()
    }
}

/// Options, passed to cryptor.
public struct Option
{
    /// Perform PKCS7 padding.
    public static let PKCS7Padding = Option(kCCOptionPKCS7Padding)
    /// Electronic Code Book Mode. Default is CBC.
    public static let ECBMode = Option(kCCOptionECBMode)
    
    private let ccValue: CCOptions
    
    /// A new Option can be created in case newer options are ever added and this library has not yet been updated.
    public init(_ ccValue: Int) {
        self.ccValue = CCOptions(ccValue);
    }
    
    /// Converts the specified options to the CC value.
    private static func CCValue(options: [Option]?) -> CCOptions {
        
        var ccOptions: CCOptions = 0;
        if let unwrappedOptions = options {
            for option in unwrappedOptions {
                ccOptions |= option.ccValue;
            }
        }
        return ccOptions;
    }
}

@objc public class Cryptor: NSObject {
    
    /// Explicity unwrapped optional as its required
    private let cryptor: CCCryptorRef!
    /// Only used when creating a Cryptor with data
    private let memoryForCryptor: NSMutableData?
    
    // MARK: Cryptor objects
    
    /// Init.
    public convenience init(operation: Operation, algorithm: RDHAlgorithm, options: [Option]?, key: NSData, initialisationVector: NSData? = nil) {
        
        let ccOptions = Option.CCValue(options)
     
        self.init(operation: operation.cValue, algorithm: algorithm.toRaw(), options: ccOptions, key: key, initialisationVector: initialisationVector)
    }
    
    /// Init for Objective-C. Marked as internal for Swift as there is a Swift specific init.
    @objc convenience init(operation: CCOperation, algorithm: CCAlgorithm, options: CCOptions, key: NSData, initialisationVector: NSData? = nil) {
        
        // Key
        let ccKeyLength = UInt(key.length)
        
        // IV
        let ccIV = (initialisationVector != nil) ? initialisationVector!.bytes : nil
        
        self.init({
            var cryptor: CCCryptorRef = nil
            // Creator a cryptor

            let status = RDHStatus.statusForOperation {
                CCCryptorCreate(operation, algorithm, options, key.bytes, ccKeyLength, ccIV, &cryptor)
            }
            if (status != RDHStatus.Success) {
                cryptor = nil
            }
            return cryptor
        })
    }
    
    /// Init with data.
    public convenience init(operation: Operation, algorithm: RDHAlgorithm, options: [Option]?, key: NSData, initialisationVector: NSData?, inout returningDataForMemory location: NSMutableData?) {
        
        let ccOptions = Option.CCValue(options)
        
        self.init(operation: operation.cValue, algorithm: algorithm.toRaw(), options: ccOptions, key: key, initialisationVector: initialisationVector, returningDataForMemory: &location)
    }
    
    /// Init with data for Objective-C. Marked as internal for Swift as there is a Swift specific init.
    @objc convenience init(operation: CCOperation, algorithm: CCAlgorithm, options: CCOptions, key: NSData, initialisationVector: NSData?, returningDataForMemory location: AutoreleasingUnsafeMutablePointer<NSMutableData?>)
    {
        assert(location != nil, "returningDataForMemory must be specified")
        
        // Key
        let ccKeyLength = UInt(key.length)
        
        // IV
        let ccIV = (initialisationVector != nil) ? initialisationVector!.bytes : nil
        
        // Data used
        var dataUsed: UInt = 0
        var ccDataLength = algorithm.contextSize
        var memoryLocation: NSMutableData
        // Use the data if some has been provided otherwise create some
        if let actualLocal = location.memory {
            memoryLocation = actualLocal
            memoryLocation.length = ccDataLength
        } else {
            memoryLocation = NSMutableData(length: ccDataLength)
        }
        location.memory = memoryLocation
        var ccData = memoryLocation.bytes
        
        self.init({
            var cryptor: CCCryptorRef = nil
            // Creator a cryptor
            let status = RDHStatus.statusForOperation {
                CCCryptorCreateFromData(operation, algorithm, options, key.bytes, ccKeyLength, ccIV, ccData, UInt(ccDataLength), &cryptor, &dataUsed)
            }
            
            if status == RDHStatus.Success {
                memoryLocation.length = Int(dataUsed)
            } else if status == RDHStatus.BufferTooSmall {
                
                // Repeat with returned size
                ccDataLength = Int(dataUsed)
                memoryLocation.length = ccDataLength
                
                // Try creating a cryptor again
                let repeatedStatus = RDHStatus.statusForOperation {
                    CCCryptorCreateFromData(operation, algorithm, options, key.bytes, ccKeyLength, ccIV, ccData, UInt(ccDataLength), &cryptor, &dataUsed)
                }
                
                if repeatedStatus != RDHStatus.Success {
                    memoryLocation.length = Int(dataUsed)
                    cryptor = nil
                }
            } else {
                cryptor = nil
            }
            return cryptor
        }, optionMemoryLocation: memoryLocation)
    }
    
    /// Init with mode.
    public convenience init(operation: Operation, mode: RDHMode, algorithm: RDHAlgorithm, padding: RDHPadding, key: NSData, initialisationVector: NSData?, tweakMaterial: NSData, numberOfRounds: Int = 0) {
        
        self.init(operation: operation.cValue, mode: mode.toRaw(), algorithm: algorithm.toRaw(), padding: padding.toRaw(), key: key, initialisationVector: initialisationVector, tweakMaterial: tweakMaterial, numberOfRounds: numberOfRounds)
    }
    
    /// Init with mode for Objective-C. Marked as internal for Swift as there is a Swift specific init.
    @objc convenience init(operation: CCOperation, mode: CCMode, algorithm: CCAlgorithm, padding: CCPadding, key: NSData, initialisationVector: NSData?, tweakMaterial: NSData, numberOfRounds: Int = 0)
    {
        // IV
        let ccIV = (initialisationVector != nil) ? initialisationVector!.bytes : nil
        
        // Key
        let ccKeyLength = UInt(key.length)
        
        // Tweak material
        let ccTweak = tweakMaterial.bytes
        let ccTweakLength = UInt(tweakMaterial.length)
        
        self.init({
            var cryptor: CCCryptorRef = nil
            // Create a cryptor
            let status = RDHStatus.statusForOperation {
                CCCryptorCreateWithMode(operation, mode, algorithm, padding, ccIV, key.bytes, ccKeyLength, ccTweak, ccTweakLength, Int32(numberOfRounds), 0, &cryptor)
            }
            
            if (status != RDHStatus.Success) {
                cryptor = nil
            }
            return cryptor
        })
    }
    
    /// Designated initialiser which sets the cryptor object to be used from the closure that creates one
    private init(_ cryptorCreationBlock: () -> CCCryptorRef!, optionMemoryLocation memoryForCryptor: NSMutableData? = nil) {
        
        let cryptor = cryptorCreationBlock()
        // Unwrap to see if the backing pointer is nil (NULL) if it is then use nil and unwrap again to raise a fatal error
        self.cryptor = ((cryptor!) != nil ? cryptor : nil)!
        self.memoryForCryptor = memoryForCryptor
//        if (cryptor!) != nil {
//            self.cryptor = cryptor
//        } else {
//            self.cryptor = nil
//            // TODO: eventually return nil
//        }
    }
    
    deinit {
        CCCryptorRelease(self.cryptor)
        if let actualMemory = self.memoryForCryptor {
            // Zero out the memory
            actualMemory.setData(NSMutableData(length: actualMemory.length))
            actualMemory.length = 0
        }
    }
    
    /// @returns the required output size for the specificed input length.
    private func outputSizeForDataInLength(dataInLength: UInt, isFinal final: Bool) -> UInt
    {
        return CCCryptorGetOutputLength(self.cryptor, dataInLength, final)
    }
    
    /// @returns the possible data out and possible error. If dataOut is nil then there will be an error.
    public func updateWithData(dataIn: NSData) -> (dataOut: NSData?, error: NSError?) {
     
        var resultantError: NSError?
        let resultantData = update(dataIn, error: &resultantError)
        
        return (dataOut: resultantData, error: resultantError)
    }
    
    /// Update for Objective-C. Marked as internal for Swift as there is a Swift specific function. @returns the data out, if this is nil then error is set.
    @objc func update(dataIn: NSData, error: NSErrorPointer = nil) -> NSData? {
        
        // Data in
        let ccDataIn = dataIn.bytes
        let ccDataInLength = UInt(dataIn.length)
        
        // Data out
        let dataOutAvailable = outputSizeForDataInLength(ccDataInLength, isFinal: false)
        var dataOut: NSMutableData? = NSMutableData(length: Int(dataOutAvailable))
        var dataOutMoved: UInt = 0
        
        // Pointer to data out - we can explicitly unwrap as we just created it above
        var ccDataOut = dataOut!.mutableBytes
        
        // Perform the cryptor operation
        let (status, success, resultantError) = cryptoBlockReturningData {
            let intStatus = CCCryptorUpdate(self.cryptor, ccDataIn, ccDataInLength, &ccDataOut, dataOutAvailable, &dataOutMoved)
            return (intStatus, dataOut, dataOutMoved)
        }
        
        if (error != nil) {
            error.memory = resultantError
        }
        
        if success {
            // Nothing to do
        } else if status == RDHStatus.BufferTooSmall {
            // Repeat with returned size
            // cryptoBlockReturningData sets the needed size
            
            // Perform the cryptor operation
            let (_, repeatedSuccess, repeatedResultantError) = cryptoBlockReturningData {
                let intStatus = CCCryptorUpdate(self.cryptor, ccDataIn, ccDataInLength, &ccDataOut, dataOutMoved, &dataOutMoved)
                return (intStatus, dataOut, dataOutMoved)
            }
            
            if (error != nil) {
                error.memory = repeatedResultantError
            }
            
            if (!repeatedSuccess) {
                // Error - zero out data
                dataOut!.length = 0
                dataOut!.setData(NSData())
                dataOut = nil
            }
            
        } else {
            // Error
            dataOut = nil
        }
        
        return dataOut
    }
    
    /// @returns the possible final data out and possible error. If dataOut is nil then there will be an error.
    public func final() -> (dataOut: NSData?, error: NSError?) {
                
        var resultantError: NSError?
        let resultantData = final(&resultantError)
        
        return (dataOut: resultantData, error: resultantError)
    }
    
    /// Final for Objective-C. Marked as internal for Swift as there is a Swift specific function. @returns the final data out, if this is nil then error is set.
    @objc func final(error: NSErrorPointer) -> NSData? {
        
        // Data out
        let dataOutAvailable = outputSizeForDataInLength(0, isFinal: true)
        var dataOut: NSMutableData? = NSMutableData(length: Int(dataOutAvailable))
        var dataOutMoved: UInt = 0
        
        // Pointer to data out - we can explicitly unwrap as we just created it above
        var ccDataOut = dataOut!.mutableBytes
        
        // Perform the cryptor operation
        let (status, success, resultantError) = cryptoBlockReturningData {
            let intStatus = CCCryptorFinal(self.cryptor, &ccDataOut, dataOutAvailable, &dataOutMoved)
            return (intStatus, dataOut, dataOutMoved)
        }
        
        if (error != nil) {
            error.memory = resultantError
        }
        
        if success {
            // Nothing to do
        } else if status == RDHStatus.BufferTooSmall {
            // Repeat with returned size
            // cryptoBlockReturningData sets the needed size
            
            // Perform the cryptor operation
            let (_, repeatedSuccess, repeatedResultantError) = cryptoBlockReturningData {
                let intStatus = CCCryptorFinal(self.cryptor, &ccDataOut, dataOutMoved, &dataOutMoved)
                return (intStatus, dataOut, dataOutMoved)
            }
            
            if (error != nil) {
                error.memory = repeatedResultantError
            }
            
            if (!repeatedSuccess) {
                // Error - zero out data
                dataOut!.length = 0
                dataOut!.setData(NSData())
                dataOut = nil
            }
            
        } else {
            // Error
            dataOut = nil
        }
        
        return dataOut
    }
    
    /// @returns true if reset was successful. false will have an error set.
    public func resetWithInitialisationVector(_ initialisationVector: NSData? = nil) -> (result: Bool, error: NSError?) {
        
        var resultantError: NSError?
        let result = resetWithInitialisationVector(initialisationVector, error: &resultantError)
        
        return (result: result, error: resultantError)
    }
    
    /// Reset for Objective-C. Marked as internal for Swift as there is a Swift specific function. @returns true if reset was successful. false will have an error set.
    @objc func resetWithInitialisationVector(_ initialisationVector: NSData? = nil, error: NSErrorPointer = nil) -> Bool {
        
        // IV
        let ccIV = (initialisationVector != nil) ? initialisationVector!.bytes : nil
        
        // Crypto operation
        let status = RDHStatus.statusForOperation {
            CCCryptorReset(self.cryptor, ccIV)
        }
        
        if error != nil {
            error.memory = status.error()
        }
        
        return status == RDHStatus.Success
    }
    
    // MARK: - Single shot encryption Swift functions
    
    public class func encrypt(algorithm: RDHAlgorithm, usingOptions options: [Option]?, withKey key: NSData, initialisationVector: NSData?, dataIn: NSData) -> (dataOut: NSData?, error: NSError?) {
        
        return cryptOperation(Operation.Encrypt, usingAlgorithm: algorithm, options: options, withKey: key, initialisationVector: initialisationVector, dataIn: dataIn)
    }
    
    public class func decrypt(algorithm: RDHAlgorithm, usingOptions options: [Option]?, withKey key: NSData, initialisationVector: NSData?, dataIn: NSData) -> (dataOut: NSData?, error: NSError?) {
        
        return cryptOperation(Operation.Decrypt, usingAlgorithm: algorithm, options: options, withKey: key, initialisationVector: initialisationVector, dataIn: dataIn)
    }
    
    /// Root Swift crypt function
    private class func cryptOperation(operation: Operation, usingAlgorithm algorithm: RDHAlgorithm, options: [Option]?, withKey key: NSData, initialisationVector: NSData?, dataIn: NSData) -> (dataOut: NSData?, error: NSError?) {
        
        let ccOptions = Option.CCValue(options)

        var resultantError: NSError?
        let resultantData = cryptOperation(operation.cValue, usingAlgorithm: algorithm.toRaw(), options: ccOptions, withKey: key, initialisationVector: initialisationVector, dataIn: dataIn, error: &resultantError)
        
        return (dataOut: resultantData, error: resultantError)
    }
    
    // MARK: - Single shot encryption Objective-C methods
    
    /// Marked as internal for Swift as there is a Swift specific function. @returns the encrypted data, if this is nil then error is set.
    @objc class func encrypt(algorithm: CCAlgorithm, usingOptions options: CCOptions, key: NSData, initialisationVector: NSData?, dataIn: NSData, error: NSErrorPointer = nil) -> NSData? {
        
        return cryptOperation(Operation.Encrypt.cValue, usingAlgorithm: algorithm, options: options, withKey: key, initialisationVector: initialisationVector, dataIn: dataIn, error: error)
    }
    
    /// Marked as internal for Swift as there is a Swift specific function. @returns the decrypted data, if this is nil then error is set.
    @objc class func decrypt(algorithm: CCAlgorithm, usingOptions options: CCOptions, key: NSData, initialisationVector: NSData?, dataIn: NSData, error: NSErrorPointer = nil) -> NSData? {
        
        return cryptOperation(Operation.Decrypt.cValue, usingAlgorithm: algorithm, options: options, withKey: key, initialisationVector: initialisationVector, dataIn: dataIn, error: error)
    }
    
    /// Exposed as the root function - this matches the API of the C CCCrypt function. Marked as internal for Swift as there is a Swift specific function. @returns the out data, if this is nil then error is set.
    @objc class func cryptOperation(operation: CCOperation, usingAlgorithm algorithm: CCAlgorithm, options: CCOptions, withKey key: NSData, initialisationVector: NSData?, dataIn: NSData, error: NSErrorPointer = nil) -> NSData? {
        
        // Key
        let ccKey = key.bytes;
        let ccKeyLength = UInt(key.length);
        
        // IV
        let ccIV = (initialisationVector != nil) ? initialisationVector!.bytes : nil

        // Data in
        let ccDataIn = dataIn.bytes
        let ccDataInLength = UInt(dataIn.length)
        
        // Data out
        let dataOutAvailable = ccDataInLength + algorithm.blockSize
        var dataOut: NSMutableData? = NSMutableData(length: Int(dataOutAvailable))
        var dataOutMoved: UInt = 0

        // Pointer to data out - we can explicitly unwrap as we just created it above
        var ccDataOut = dataOut!.mutableBytes
        
        // Perform the cryptor operation
        let (status, success, resultantError) = cryptoBlockReturningData {
            let intStatus = CCCrypt(operation, algorithm, options, ccKey, ccKeyLength, ccIV, ccDataIn, ccDataInLength, ccDataOut, dataOutAvailable, &dataOutMoved)
            return (intStatus, dataOut, dataOutMoved)
        }
        
        if (error != nil) {
            error.memory = resultantError
        }
        
        if success {
            // Nothing to do
        } else if status == RDHStatus.BufferTooSmall {
            // cryptoBlockReturningData with returned size
            // Cleanup sets the needed size
            
            // Perform the cryptor operation
            let (_, repeatedSuccess, repeatedResultantError) = cryptoBlockReturningData {
                let intStatus = CCCrypt(operation, algorithm, options, ccKey, ccKeyLength, ccIV, ccDataIn, ccDataInLength, ccDataOut, dataOutMoved, &dataOutMoved)
                return (intStatus, dataOut, dataOutMoved)
            }
            
            if (error != nil) {
                error.memory = repeatedResultantError
            }
            
            if (!repeatedSuccess) {
                // Error - zero out data
                dataOut!.length = 0
                dataOut!.setData(NSData())
                dataOut = nil
            }
            
        } else {
            // Error
            dataOut = nil
        }
        
        return dataOut
    }
    
    /// @returns random data of length
    @objc public class func randomDataWithLength(length: Int) -> NSData? {
        assert(length >= 0, "Length must be greater or equal than 0")
        
        let data = NSMutableData(length: length)
        
        var status = false
        if NSFoundationVersionNumber > NSFoundationVersionNumber_iOS_7_1 {
            status = CCRandomGenerateBytes(data.mutableBytes, UInt(length)) == CCRNGStatus(kCCSuccess)
        } else {
            status = SecRandomCopyBytes(kSecRandomDefault, UInt(length), UnsafeMutablePointer<UInt8>(data.mutableBytes)) == 0
        }
        return status ? data : nil
    }
}

/// Closure that can return and clean up the data
private func cryptoBlockReturningData(block: () -> (CCStatus, NSMutableData?, UInt)) -> (status: RDHStatus, success: Bool, error: NSError?) {
    
    let (intStatus, dataOut, dataOutMoved) = block()
    let status = RDHStatus.fromInt(intStatus)
    
    let (resultSuccess, resultantError) = cleanUpOutData(dataOut, movedOutLength: dataOutMoved, forResultStatus: status)
    
    return (status, resultSuccess, resultantError)
}

/// Checks if the the opertaion was succesful and then trims the data to the needed size. If there was an error success will be false with a error
private func cleanUpOutData(dataOut: NSMutableData!, movedOutLength dataOutMoved: UInt, forResultStatus status: RDHStatus) -> (success: Bool, error: NSError?) {
    
    var success = false
    var error: NSError? = nil
    if status == RDHStatus.Success {
        // Fix data to final length
        dataOut.length = Int(dataOutMoved)
        success = true
    } else if status == RDHStatus.BufferTooSmall {
        
        // dataOutMoved now contains the needed size
        dataOut.length = Int(dataOutMoved)
        
    } else {
        error = status.error()
        // Clear any out data
        dataOut.length = 0
    }
    
    return (success, error)
}
