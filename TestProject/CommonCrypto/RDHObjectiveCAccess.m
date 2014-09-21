//
//  RDHObjectiveCAccess.m
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 16/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

@import RDHCommonCrypto;

#import "RDHCommonCrypto-Swift.h"

void RDHCheck()
{
    NSMutableData *data;
    Cryptor *c = [[Cryptor alloc] initWithOperation:kCCEncrypt algorithm:RDHAlgorithmAES options:RDHCryptorOptionPKCS7Padding key:[@"TEST" dataUsingEncoding:NSUTF8StringEncoding] initialisationVector:nil returningDataForMemory:&data];
    
    data = [NSMutableData new];
    c = [[Cryptor alloc] initWithOperation:kCCEncrypt algorithm:RDHAlgorithmAES options:RDHCryptorOptionPKCS7Padding key:[@"TEST" dataUsingEncoding:NSUTF8StringEncoding] initialisationVector:nil returningDataForMemory:&data];

//    c = [[Cryptor alloc] initWithOperation:kCCEncrypt algorithm:RDHAlgorithmAES options:RDHCryptorOptionPKCS7Padding key:[@"TEST" dataUsingEncoding:NSUTF8StringEncoding] initialisationVector:nil returningDataForMemory:NULL];
}
