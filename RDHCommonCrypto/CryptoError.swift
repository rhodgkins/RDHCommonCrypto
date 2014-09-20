//
//  CryptoError.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 15/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import Foundation

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
        
        return NSError(domain: "", code: Int(self.toRaw()), userInfo: (message != nil) ? [NSLocalizedDescriptionKey : message!] : nil)
    }
    
    static func fromInt(intStatus: CCStatus) -> RDHStatus {
        
        return fromRaw(intStatus) ?? .Unknown
    }
}
