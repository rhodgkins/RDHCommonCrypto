//
//  KeyDerivationTests.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 21/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import XCTest

import RDHCommonCrypto

let Password = "A password!"
let Salt = secureRandomData(100)!

let TestCalibration = false

class KeyDerivationTests: XCTestCase {

    func testPBKDF2() {
        
        let (key, error) = KeyDerivation.PBKDFWithAlgorithm(RDHPBKDFAlgorithm.PBKDF2, usingPassword: Password, withSalt: Salt, pseudoRandomAlgorithm: RDHPseudoRandomAlgorithm.HmacAlgSHA1, numberOfRounds: 10)
    }
    
    func testPBKDF2Calibration() {
        
        let rounds = KeyDerivation.CalibratePBKDF2UsingPassword(Password, salt: Salt, pseudoRandomAlgorithm: RDHPseudoRandomAlgorithm.HmacAlgSHA512, targettedDuration: 0.005)
        
        let (key, error) = KeyDerivation.PBKDFWithAlgorithm(RDHPBKDFAlgorithm.PBKDF2, usingPassword: Password, withSalt: Salt, pseudoRandomAlgorithm: RDHPseudoRandomAlgorithm.HmacAlgSHA1, numberOfRounds: rounds)
    }
    
    func testAgainstCAPI() {
        
        let algorithms = ["PBKDF2" : RDHPBKDFAlgorithm.PBKDF2]
        let prfs = ["SHA-1" : RDHPseudoRandomAlgorithm.HmacAlgSHA1,
            "SHA-224" : RDHPseudoRandomAlgorithm.HmacAlgSHA224,
            "SHA-256" : RDHPseudoRandomAlgorithm.HmacAlgSHA256,
            "SHA-384" : RDHPseudoRandomAlgorithm.HmacAlgSHA384,
            "SHA-512" : RDHPseudoRandomAlgorithm.HmacAlgSHA512]
        
        for (algKey, alg) in algorithms {
            for (prfKey, prf) in prfs {
                
                let message = "\(algKey) using \(prfKey)"
                NSLog(message)
                
                func randomStringWithLength(var length: Int) -> String {
                    var s = ""
                    while (countElements(s) < length) {
                        s += "h"
                    }
                    return s
                }
                
                let passwordLength = random() % 64
                let saltLength = random() % 256
                let derivedKeyLength = random() % 128
                
                let password = randomStringWithLength(passwordLength)
                let salt = secureRandomData(saltLength)
                let duration = 0.05
                let durationMS = UInt32(ceil(duration * 1000.0))
                
                if TestCalibration {
                    // Calibration
                    
                    // Swift
                    let actualRounds = KeyDerivation.calibratePBKDFWithAlgorithm(alg, password: password, salt: salt, pseudoRandomAlgorithm: prf, targettedDuration: duration, derivedKeyLength: derivedKeyLength)
                    
                    // C API
                    let expectedRounds = Int(CCCalibratePBKDF(alg.toRaw(), strlen(password), UInt(salt?.length ?? 0), prf.toRaw(), UInt(derivedKeyLength), durationMS))
                    
                    XCTAssertEqualWithAccuracy(Double(actualRounds), Double(expectedRounds), Double(expectedRounds) * 0.25, "Rounds not correct: \(message)")
                }
                    
                // Derivation
                
                let rounds = 1 + (random() % 50000)
                
                // Swift
                let (actualKey, actualError) = KeyDerivation.PBKDFWithAlgorithm(alg, usingPassword: password, withSalt: salt, pseudoRandomAlgorithm: prf, numberOfRounds: rounds, derivedKeyLength: derivedKeyLength)
                
                // C API
                let expectedKey = NSMutableData(length: derivedKeyLength)
                let expectedStatus = Int(CCKeyDerivationPBKDF(alg.toRaw(), password, strlen(password), UnsafePointer<UInt8>(salt?.bytes ?? nil), UInt(saltLength), prf.toRaw(), uint(rounds), UnsafeMutablePointer<UInt8>(expectedKey.mutableBytes), UInt(derivedKeyLength)))
                
                if expectedStatus == kCCSuccess {
                    if let key = actualKey {
                        XCTAssertTrue(key == expectedKey, "Derived keys not the same: \(message)")
                    } else {
                        XCTAssertNotNil(actualKey, "Returned nil key: \(message)")
                    }
                    XCTAssertNil(actualError, "Error not nil: \(message)")
                } else {
                    XCTAssertNotNil(actualError, "Error nil: \(message)")
                    XCTAssertNil(actualKey, "Derived key not nil: \(message)")
                }
            }
        }
    }
}
