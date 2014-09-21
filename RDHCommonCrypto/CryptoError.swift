//
//  CryptoError.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 15/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation

let RDHCommonCryptoErrorDomain = "RDHCommonCryptoErrorDomain"

extension RDHStatus {
    
    func error() -> NSError? {
        
        var message: String? = nil
        
        switch (self) {
            case .Success:
                return nil
                
            case .ParameterError:
                message = "Illegal parameter value."
                
            case .BufferTooSmall:
                message = "Insufficent buffer provided for specified operation."
                
            case .MemoryFailure:
                message = "Memory allocation failure."
                
            case .AlignmentError:
                message = "Input size was not aligned properly."
                
            case .DecodeError:
                message = "Input data did not decode or decrypt properly."
                
            case .Unimplemented:
                message = "Function not implemented for the current algorithm."
                
            case .Overflow:
                message = nil
                
            case .RandomNumberGeneratorFailure:
                message = nil
                
            case .Unknown:
                message = nil
        }
        
        return NSError(domain: RDHCommonCryptoErrorDomain, code: Int(self.toRaw()), userInfo: (message != nil) ? [NSLocalizedDescriptionKey : message!] : nil)
    }
    
    static func fromInt(intStatus: CCStatus) -> RDHStatus {
        
        return fromRaw(intStatus) ?? .Unknown
    }
    
    /// Closure that converts a crypto operation status
    static func statusForOperation(block: () -> CCStatus) -> RDHStatus {
        let intStatus = block()
        return RDHStatus.fromInt(intStatus)
    }
}

/// Checks if the the operation was succesful and then trims the data to the needed size. If there was an error success will be false with a error
func cleanUpOutData(dataOut: NSMutableData!, movedOutLength dataOutMoved: UInt, forResultStatus status: RDHStatus) -> (success: Bool, error: NSError?) {
    
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
