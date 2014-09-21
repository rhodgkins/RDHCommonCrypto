//
//  KeyDerivation.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 21/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation

public extension String {
    public var length: Int {
        return (self as NSString).length
    }
}

private extension CCPseudoRandomAlgorithm {
    var defaultDerivedKeyLength: Int {
        switch(Int(self)) {
            case kCCPRFHmacAlgSHA1:
                return 160 / 8
            case kCCPRFHmacAlgSHA224:
                return 224 / 8
            case kCCPRFHmacAlgSHA256:
                return 256 / 8
            case kCCPRFHmacAlgSHA384:
                return 384 / 8
            case kCCPRFHmacAlgSHA512:
                return 512 / 8
            default:
                return 128 / 8
        }
    }
}

private extension RDHPseudoRandomAlgorithm {
    var defaultDerivedKeyLength: Int {
        return self.toRaw().defaultDerivedKeyLength
    }
}

// Don't extend NSObject as there are no instance methods
@objc public class KeyDerivation {
    
    /// Cannot instantiate this class
    private init() {
        assertionFailure("KeyDerivation cannot be instantiated")
    }
    
    // MARK: - PBKDF2: Key derivation

    /// Instead of specifiying the number of rounds a duration can be provided when using PBKDF2.
    class func PBKDF2UsingPassword(password: String!, withSalt salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, targettedDuration: NSTimeInterval, derivedKeyLength: Int? = nil) -> (derivedKey: NSData?, error: NSError?) {
        
        let algorithm = RDHPBKDFAlgorithm.PBKDF2
        
        return PBKDF2UsingPassword(password, withSalt: salt, pseudoRandomAlgorithm: prf, targettedDuration: targettedDuration, derivedKeyLength: derivedKeyLength)
    }
    
    class func PBKDF2UsingPassword(password: String!, withSalt salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, numberOfRounds rounds: Int = 1, derivedKeyLength: Int? = nil) -> (derivedKey: NSData?, error: NSError?) {
        
        return PBKDFWithAlgorithm(RDHPBKDFAlgorithm.PBKDF2, usingPassword: password, withSalt: salt, pseudoRandomAlgorithm: prf, numberOfRounds: rounds, derivedKeyLength: derivedKeyLength)
    }
    
    // MARK: - Generic PBKDF: Key derivation
    
    /// Instead of specifiying the number of rounds a duration can be provided.
    class func PBKDFWithAlgorithm(algorithm: RDHPBKDFAlgorithm, usingPassword password: String!, withSalt salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, targettedDuration: NSTimeInterval, derivedKeyLength: Int? = nil) -> (derivedKey: NSData?, error: NSError?) {
        
        let rounds = calibratePBKDFWithAlgorithm(algorithm, password: password, salt: salt, pseudoRandomAlgorithm: prf, targettedDuration: targettedDuration, derivedKeyLength: derivedKeyLength)
        
        return PBKDFWithAlgorithm(RDHPBKDFAlgorithm.PBKDF2, usingPassword: password, withSalt: salt, pseudoRandomAlgorithm: prf, numberOfRounds: rounds, derivedKeyLength: derivedKeyLength)
    }
    
    /// @returns the derived key data data, if this is nil then error is set.
    class func PBKDFWithAlgorithm(algorithm: RDHPBKDFAlgorithm, usingPassword password: String!, withSalt salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, numberOfRounds rounds: Int = 1, derivedKeyLength: Int? = nil) -> (derivedKey: NSData?, error: NSError?) {
        
        var usedDerivedKeyLength = derivedKeyLength ?? prf.defaultDerivedKeyLength
        
        var resultantError: NSError?
        let resultantDerivedKey = PBKDFWithAlgorithm(algorithm.toRaw(), password: password, salt: salt, pseudoRandomAlgorithm: prf.toRaw(), numberOfRounds: rounds, derivedKeyLength: usedDerivedKeyLength, error: &resultantError)
        
        return (resultantDerivedKey, resultantError)
    }
    
    /// Objective-C method. Marked as internal for Swift as there is a Swift specific function. @returns the encrypted data, if this is nil then error is set.
    @objc class func PBKDFWithAlgorithm(algorithm: CCPBKDFAlgorithm, password: String!, salt: NSData?, pseudoRandomAlgorithm prf: CCPseudoRandomAlgorithm, numberOfRounds rounds: Int, derivedKeyLength: Int, error: NSErrorPointer = nil) -> NSData? {
        
        assert(rounds > 0, "Number of rounds must be greater than 0: \(rounds)")
        assert(derivedKeyLength > 0, "The expected derived key length must be greater than 0: \(derivedKeyLength)")
        
        // Salt
        var saltLength: UInt = 0
        var saltBytes: UnsafePointer<UInt8> = nil
        if let actualSalt = salt {
            saltLength = UInt(actualSalt.length)
            saltBytes = UnsafePointer<UInt8>(actualSalt.bytes)
        }
        
        // Derived key
        var derivedKey: NSMutableData? = NSMutableData(length: derivedKeyLength)
        let derivedKeyChars = UnsafeMutablePointer<UInt8>(derivedKey!.mutableBytes)
        
        // Operation
        let status = RDHStatus.statusForOperation {
            CCKeyDerivationPBKDF(algorithm, password, strlen(password), saltBytes, saltLength, prf, uint(rounds), derivedKeyChars, UInt(derivedKeyLength))
        }
        
        if (status != RDHStatus.Success) {
            derivedKey!.length = 0
            derivedKey = nil
        }
        if (error != nil) {
            error.memory = status.error()
        }
        
        return derivedKey
    }
    
    // MARK: - PBKDF2: Round calibration
    
    /// @returns the number of iterations to use for the desired processing time when using PBKDF2.
    public class func calibratePBKDF2UsingPassword(password: String!, salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, targettedDuration: NSTimeInterval, derivedKeyLength: Int? = nil) -> Int {

        return calibratePBKDFWithAlgorithm(RDHPBKDFAlgorithm.PBKDF2, password: password, salt: salt, pseudoRandomAlgorithm: prf, targettedDuration: targettedDuration, derivedKeyLength: derivedKeyLength)
    }
    
    // MARK: - Generic PBKDF: Round calibration
    
    /// @returns the number of iterations to use for the desired processing time.
    public class func calibratePBKDFWithAlgorithm(algorithm: RDHPBKDFAlgorithm, password: String!, salt: NSData?, pseudoRandomAlgorithm prf: RDHPseudoRandomAlgorithm, targettedDuration: NSTimeInterval, derivedKeyLength: Int? = nil) -> Int {
        
        var usedDerivedKeyLength = derivedKeyLength ?? prf.defaultDerivedKeyLength
        
        return calibratePBKDFWithAlgorithm(algorithm.toRaw(), password: password, salt: salt, pseudoRandomAlgorithm: prf.toRaw(), targettedDuration: targettedDuration, derivedKeyLength: usedDerivedKeyLength)
    }
    
    /// Objective-C method. Marked as internal for Swift as there is a Swift specific function. @returns the number of iterations to use for the desired processing time.
    @objc class func calibratePBKDFWithAlgorithm(algorithm: CCPBKDFAlgorithm, password: String!, salt: NSData?, pseudoRandomAlgorithm prf: CCPseudoRandomAlgorithm, targettedDuration: NSTimeInterval, derivedKeyLength: Int) -> Int {
        
        assert(derivedKeyLength > 0, "The expected derived key length must be greater than 0: \(derivedKeyLength)")
        assert(targettedDuration > 0, "The targetted duration must be greater than 0: \(targettedDuration)")
        
        // Salt
        var saltLength = salt?.length ?? 0
        
        // Duration
        let durationMillis = UInt32(ceil(targettedDuration * 1000))
        
        // Operation
        let rounds = CCCalibratePBKDF(algorithm, strlen(password), UInt(saltLength), prf, UInt(derivedKeyLength), durationMillis)
        
        return Int(rounds)
    }
}