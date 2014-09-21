//
//  RDHCommonCryptoEnums.h
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 16/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

#import <CommonCrypto/CommonCrypto.h>

@import Foundation;

/**
 * This file contains all of the CommonCrypto enums which have been correctly defined so they can be used in Swift.
 */

#pragma mark - Cryptor

/// Encryption algorithms implemented by this module.
typedef NS_ENUM(CCAlgorithm, RDHAlgorithm)
{
    /// Advanced Encryption Standard, 128-bit block
    RDHAlgorithmAES = kCCAlgorithmAES,
    /**
     * Advanced Encryption Standard, 128-bit block.
     *
     * This is kept for historical reasons.  It's preferred now to use AES since 128-bit blocks are part of the standard.
     */
    RDHAlgorithmAES128 = kCCAlgorithmAES128,
    /// Data Encryption Standard
    RDHAlgorithmDES = kCCAlgorithmDES,
    /// Triple-DES, three key, EDE configuration
    RDHAlgorithmTripleDES = kCCAlgorithm3DES,
    /// CAST
    RDHAlgorithmCAST = kCCAlgorithmCAST,
    /// RC4 stream cipher
    RDHAlgorithmRC4 = kCCAlgorithmRC4,
    /// RC2 stream cipher
    RDHAlgorithmRC2 = kCCAlgorithmRC2,
    /// Blowfish block cipher
    RDHAlgorithmBlowfish = kCCAlgorithmBlowfish
};

/**
 * Key sizes, in bytes, for supported algorithms.  Use these constants to select any keysize variants you wish to use for algorithms that support them (ie AES-128, AES-192, AES-256)
 *
 * DES and TripleDES have fixed key sizes.
 * AES has three discrete key sizes.
 * CAST and RC4 have variable key sizes.
 */
typedef enum : NSInteger
{
    /// 128 bit AES key size.
    RDHKeySizeAES128 = kCCKeySizeAES128,
    /// 192 bit AES key size.
    RDHKeySizeAES192 = kCCKeySizeAES192,
    /// 256 bit AES key size.
    RDHKeySizeAES256 = kCCKeySizeAES256,
    /// DES key size.
    RDHKeySizeDES = kCCKeySizeDES,
    /// Triple DES key size.
    RDHKeySizeTripleDES = kCCKeySize3DES,
    /// CAST minimum key size.
    RDHKeySizeMinCAST = kCCKeySizeMinCAST,
    /// CAST maximum key size.
    RDHKeySizeMaxCAST = kCCKeySizeMaxCAST,
    /// RC4 minimum key size.
    RDHKeySizeMinRC4 = kCCKeySizeMinRC4,
    /// RC4 maximum key size.
    RDHKeySizeMaxRC4 = kCCKeySizeMaxRC4,
    /// RC2 minimum key size.
    RDHKeySizeMinRC2 = kCCKeySizeMinRC2,
    /// RC2 maximum key size.
    RDHKeySizeMaxRC2 = kCCKeySizeMaxRC2,
    /// Blowfish minimum key size.
    RDHKeySizeMinBlowfish = kCCKeySizeMinBlowfish,
    /// Blowfish maximum key size.
    RDHKeySizeMaxBlowfish = kCCKeySizeMaxBlowfish
} RDHKeySize;

/// Block sizes, in bytes, for supported algorithms.
typedef enum : NSInteger
{
    /// AES block size (currently, only 128-bit blocks are supported).
    RDHBlockSizeAES128 = kCCBlockSizeAES128,
    /// DES block size.
    RDHBlockSizeDES = kCCBlockSizeDES,
    /// Triple DES block size.
    RDHBlockSizeTripleDES = kCCBlockSize3DES,
    /// CAST block size.
    RDHBlockSizeCAST = kCCBlockSizeCAST,
    /// RC2 block size.
    RDHBlockSizeRC2 = kCCBlockSizeRC2,
    /// Blowfish block size.
    RDHBlockSizeBlowfish = kCCBlockSizeBlowfish,
} RDHBlockSize;

// TODO: correct comments below
/**
 * Minimum context sizes, for caller-allocated CCCryptorRefs.
 * To minimize dynamic allocation memory, a caller can create a CCCryptorRef by passing caller-supplied memory to the CCCryptorCreateFromData() function.
 
 * These constants define the minimum amount of memory, in bytes, needed for CCCryptorRefs for each supported algorithm.
 
 * Note: these constants are valid for the current version of this library; they may change in subsequent releases, so applications wishing to allocate their own memory for use in creating CCCryptorRefs must be prepared to deal with a kCCBufferTooSmall return from CCCryptorCreateFromData().
 *
 * See discussion for the CCCryptorCreateFromData() function.
 */
typedef enum : NSInteger
{
    /// Minimum context size for kCCAlgorithmAES128.
    RDHContextSizeAES128 = kCCContextSizeAES128,
    /// Minimum context size for kCCAlgorithmDES.
    RDHContextSizeDES = kCCContextSizeDES,
    /// Minimum context size for kCCAlgorithm3DES.
    RDHContextSizeTripleDES = kCCContextSize3DES,
    /// Minimum context size for kCCAlgorithmCAST.
    RDHContextSizeCAST = kCCContextSizeCAST,
    /// Minimum context size for kCCAlgorithmRC4.
    RDHContextSizeRC4 = kCCContextSizeRC4
} RDHContextSize;

/// Options flags, passed to Cryptor.
typedef NS_OPTIONS(uint32_t, RDHCryptorOption) {
    /// Perform PKCS7 padding.
    RDHCryptorOptionPKCS7Padding = kCCOptionPKCS7Padding,
    /// Electronic Code Book Mode. Default is CBC.
    RDHCryptorOptionECBMode = kCCOptionECBMode
};

/// Padding for Block Ciphers. These are the padding options available for block modes.
typedef NS_ENUM(CCPadding, RDHPadding) {
    /// No padding.
    RDHPaddingNone = ccNoPadding,
    /// PKCS7 Padding.
    RDHPaddingPKCS7 = ccPKCS7Padding
};

/// These are the selections available for modes of operation for use with block ciphers.  If RC4 is selected as the cipher (a stream cipher) the only correct mode is RDHModeRC4.
typedef NS_ENUM(CCMode, RDHMode) {
    /// Electronic Code Book Mode.
    RDHModeECB = kCCModeECB,
    /// Cipher Block Chaining Mode.
    RDHModeCBC = kCCModeCBC,
    /// Cipher Feedback Mode.
    RDHModeCFB = kCCModeCFB,
    /// Counter Mode.
    RDHModeCTR = kCCModeCTR,
    /// Unimplemented for now (not included)
    RDHModeF8 = kCCModeF8,
    /// Unimplemented for now (not included)
    RDHModeLRW = kCCModeLRW,
    /// Output Feedback Mode.
    RDHModeOFB = kCCModeOFB,
    /// XEX-based Tweaked CodeBook Mode.
    RDHModeXTS = kCCModeXTS,
    /// RC4 as a streaming cipher is handled internally as a mode.
    RDHModeRC4 = kCCModeRC4,
    /// Cipher Feedback Mode producing 8 bits per round.
    RDHModeCFB8 = kCCModeCFB8
};


#pragma mark - KeyDerivation

/// Public key derivation function algorithms.
typedef NS_ENUM(CCPBKDFAlgorithm, RDHPBKDFAlgorithm) {
    /// Version 2
    RDHPBKDFAlgorithmPBKDF2 = kCCPBKDF2
};

/// The Pseudo Random Algorithms used for the derivation iterations.
typedef NS_ENUM(CCPseudoRandomAlgorithm, RDHPseudoRandomAlgorithm) {
    RDHPseudoRandomAlgorithmHmacAlgSHA1 = kCCPRFHmacAlgSHA1,
    RDHPseudoRandomAlgorithmHmacAlgSHA224 = kCCPRFHmacAlgSHA224,
    RDHPseudoRandomAlgorithmHmacAlgSHA256 = kCCPRFHmacAlgSHA256,
    RDHPseudoRandomAlgorithmHmacAlgSHA384 = kCCPRFHmacAlgSHA384,
    RDHPseudoRandomAlgorithmHmacAlgSHA512 = kCCPRFHmacAlgSHA512
};


#pragma mark - SymmetricKeyWrap

typedef NS_ENUM(CCWrappingAlgorithm, RDHWrappingAlgorithm) {
    /// AES Keywrapping (rfc3394)
    RDHWrappingAlgorithmAES = kCCWRAPAES
};


#pragma mark - CryptoError

/// Return values from CommonCryptor operations.
typedef NS_ENUM(CCStatus, RDHStatus)
{
    /// Operation completed normally.
    RDHStatusSuccess = kCCSuccess,
    /// Illegal parameter value.
    RDHStatusParameterError = kCCParamError,
    /// Insufficent buffer provided for specified operation.
    RDHStatusBufferTooSmall = kCCBufferTooSmall,
    /// Memory allocation failure.
    RDHStatusMemoryFailure = kCCMemoryFailure,
    /// Input size was not aligned properly.
    RDHStatusAlignmentError = kCCAlignmentError,
    /// Input data did not decode or decrypt properly.
    RDHStatusDecodeError = kCCDecodeError,
    /// Function not implemented for the current algorithm.
    RDHStatusUnimplemented = kCCUnimplemented,
    RDHStatusOverflow = kCCOverflow,
    RDHStatusRandomNumberGeneratorFailure = kCCRNGFailure,
    RDHStatusUnknown = INT32_MAX
};

typedef CCCryptorStatus RDHCryptorStatus;

