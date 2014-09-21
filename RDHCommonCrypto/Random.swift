//
//  Random.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 21/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation

public func secureRandomData(withLength: Int) -> NSData? {
    
    let length = withLength
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

@objc public class Random {
    
    /// @returns random data of length
    @objc public class func secureRandomDataWithLength(length: Int) -> NSData? {
        return secureRandomData(length)
    }
}