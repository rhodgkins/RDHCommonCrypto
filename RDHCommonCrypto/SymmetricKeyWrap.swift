//
//  SymmetricKeyWrap.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 21/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation

public extension RDHWrappingAlgorithm {
    
    /// Wrap the key using the receiver
    public func wrap(rawKey: NSData, withKeyEncryptionKey kek: NSData, usingIV iv: NSData = SymmetricKeyWrap.RFC3394IV()) -> (wrappedKey: NSData?, error: NSError?) {
        
        var resultantError: NSError? = nil
        let wrappedKey = SymmetricKeyWrap.wrapWithAlgorithm(self.toRaw(), usingIV: iv, keyEncryptionKey: kek, rawKey: rawKey, error: &resultantError)
        
        return (wrappedKey, resultantError)
    }
    
    /// Unwrap the key using the receiver
    public func unwrap(wrappedKey: NSData, withKeyEncryptionKey kek: NSData, usingIV iv: NSData = SymmetricKeyWrap.RFC3394IV()) -> (rawKey: NSData?, error: NSError?) {
        
        var resultantError: NSError? = nil
        let rawKey = SymmetricKeyWrap.unwrapWithAlgorithm(self.toRaw(), usingIV: iv, keyEncryptionKey: kek, wrappedKey: wrappedKey, error: &resultantError)
        
        return (rawKey, resultantError)
    }
    
    public func wrappedKeyLength(rawKeyLength: Int) -> Int {
        return SymmetricKeyWrap.wrappedLengthWithAlgorithm(self.toRaw(), forRawKeyLength: rawKeyLength)
    }
    
    public func unwrappedKeyLength(wrappedKeyLength: Int) -> Int {
        return SymmetricKeyWrap.unwrappedLengthWithAlgorithm(self.toRaw(), forWrappedKeyLength: wrappedKeyLength)
    }
}

// Don't extend NSObject as there are no instance methods
@objc public class SymmetricKeyWrap {
    
    /// Cannot instantiate this class
    private init() {
        assertionFailure("KeyDerivation cannot be instantiated")
    }
    
    // TODO: should be class property
//    @objc public class let RFC3394IV = NSData(bytes: CCrfc3394_iv, length: Int(CCrfc3394_ivLen))
    @objc public class func RFC3394IV() -> NSData {
        return NSData(bytes: CCrfc3394_iv, length: Int(CCrfc3394_ivLen))
    }
    
    @objc public class func wrapWithAlgorithm(algorithm: CCWrappingAlgorithm, usingIV iv: NSData?, keyEncryptionKey kek: NSData, rawKey: NSData, error: NSErrorPointer) -> NSData? {
        
        // IV
        var ivBytes: UnsafePointer<UInt8>
        var ivLength: UInt
        if let actualIV = iv {
            ivBytes = UnsafePointer<UInt8>(actualIV.bytes)
            ivLength = UInt(actualIV.length)
        } else {
            let defaultIV = RFC3394IV()
            ivBytes = UnsafePointer<UInt8>(defaultIV.bytes)
            ivLength = UInt(defaultIV.length)
        }
        
        // KEK
        let kekLength = UInt(kek.length)
        let kekBytes = UnsafePointer<UInt8>(kek.bytes)
        
        // Raw key
        let rawKeyLength = UInt(rawKey.length)
        let rawKeyBytes = UnsafePointer<UInt8>(rawKey.bytes)
        
        // Wrapped key
        let wrappedKeyLength = UInt(wrappedLengthWithAlgorithm(algorithm, forRawKeyLength: Int(rawKeyLength)))
        var wrappedKey: NSMutableData? = NSMutableData(length: Int(wrappedKeyLength))
        let wrappedKeyBytes = UnsafeMutablePointer<UInt8>(wrappedKey!.mutableBytes)
        var returnedWrappedKeyLength: UInt = 0
        
        // Operation
        let status = RDHStatus.statusForOperation {
            CCSymmetricKeyWrap(algorithm, ivBytes, ivLength, kekBytes, kekLength, rawKeyBytes, rawKeyLength, wrappedKeyBytes, &returnedWrappedKeyLength)
        }
        
        let (success, resultantError) = cleanUpOutData(wrappedKey, movedOutLength: returnedWrappedKeyLength, forResultStatus: status)
        
        if (error != nil) {
            error.memory = resultantError
        }
        
        if success {
            // Nothing to do
        } else if status == RDHStatus.BufferTooSmall {
            // Repeat with returned size
            // cryptoBlockReturningData sets the needed size
            let repeatedStatus = RDHStatus.statusForOperation {
                CCSymmetricKeyWrap(algorithm, ivBytes, ivLength, kekBytes, kekLength, rawKeyBytes, rawKeyLength, wrappedKeyBytes, &returnedWrappedKeyLength)
            }
            
            // Perform the cryptor operation
            let (repeatedSuccess, repeatedResultantError) = cleanUpOutData(wrappedKey, movedOutLength: returnedWrappedKeyLength, forResultStatus: repeatedStatus)
            
            if (error != nil) {
                error.memory = repeatedResultantError
            }
            
            if (!repeatedSuccess) {
                // Error - zero out data
                wrappedKey!.setData(NSData())
                wrappedKey!.length = 0
                wrappedKey = nil
            }
            
        } else {
            // Error
            wrappedKey = nil
        }
        
        return wrappedKey
    }
    
    @objc public class func unwrapWithAlgorithm(algorithm: CCWrappingAlgorithm, usingIV iv: NSData?, keyEncryptionKey kek: NSData, wrappedKey: NSData, error: NSErrorPointer) -> NSData? {
        
        // IV
        var ivBytes: UnsafePointer<UInt8>
        var ivLength: UInt
        if let actualIV = iv {
            ivBytes = UnsafePointer<UInt8>(actualIV.bytes)
            ivLength = UInt(actualIV.length)
        } else {
            let defaultIV = RFC3394IV()
            ivBytes = UnsafePointer<UInt8>(defaultIV.bytes)
            ivLength = UInt(defaultIV.length)
        }
        
        // KEK
        var kekLength = UInt(kek.length)
        var kekBytes = UnsafePointer<UInt8>(kek.bytes)
        
        // Wrapped key
        let wrappedKeyLength = UInt(wrappedKey.length)
        let wrappedKeyBytes = UnsafeMutablePointer<UInt8>(wrappedKey.bytes)
        
        // Raw key
        let rawKeyLength = UInt(unwrappedLengthWithAlgorithm(algorithm, forWrappedKeyLength: Int(wrappedKeyLength)))
        var rawKey: NSMutableData? = NSMutableData(length: Int(rawKeyLength))
        let rawKeyBytes = UnsafeMutablePointer<UInt8>(rawKey!.mutableBytes)
        var returnedRawKeyLength: UInt = 0
        
        // Operation
        let status = RDHStatus.statusForOperation {
            CCSymmetricKeyUnwrap(algorithm, ivBytes, ivLength, kekBytes, kekLength, wrappedKeyBytes, wrappedKeyLength, rawKeyBytes, &returnedRawKeyLength)
        }
        
        let (success, resultantError) = cleanUpOutData(rawKey, movedOutLength: returnedRawKeyLength, forResultStatus: status)
        
        if (error != nil) {
            error.memory = resultantError
        }
        
        if success {
            // Nothing to do
        } else if status == RDHStatus.BufferTooSmall {
            // Repeat with returned size
            // cryptoBlockReturningData sets the needed size
            let repeatedStatus = RDHStatus.statusForOperation {
                CCSymmetricKeyUnwrap(algorithm, ivBytes, ivLength, kekBytes, kekLength, wrappedKeyBytes, wrappedKeyLength, rawKeyBytes, &returnedRawKeyLength)
            }
            
            // Perform the cryptor operation
            let (repeatedSuccess, repeatedResultantError) = cleanUpOutData(rawKey, movedOutLength: returnedRawKeyLength, forResultStatus: repeatedStatus)
            
            if (error != nil) {
                error.memory = repeatedResultantError
            }
            
            if (!repeatedSuccess) {
                // Error - zero out data
                rawKey!.setData(NSData())
                rawKey!.length = 0
                rawKey = nil
            }
            
        } else {
            // Error
            rawKey = nil
        }
        
        return rawKey
    }
    
    /// Objective-C function. For Swift use RDHWrappingAlgorithm.wrappedKeyLength(rawKeyLength:)
    @objc public class func wrappedLengthWithAlgorithm(algorithm: CCWrappingAlgorithm, forRawKeyLength rawKeyLength: Int) -> Int {
    
        return Int(CCSymmetricWrappedSize(algorithm, UInt(rawKeyLength)))
    }
    
    /// Objective-C function. For Swift use RDHWrappingAlgorithm.unwrappedKeyLength(wrappedKeyLength:)
    @objc public class func unwrappedLengthWithAlgorithm(algorithm: CCWrappingAlgorithm, forWrappedKeyLength wrappedKeyLength: Int) -> Int {
        
        return Int(CCSymmetricUnwrappedSize(algorithm, UInt(wrappedKeyLength)))
    }
}
