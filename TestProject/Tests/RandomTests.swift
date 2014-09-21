//
//  RandomTests.swift
//  RDHCommonCrypto
//
//  Created by Richard Hodgkins on 21/09/2014.
//  Copyright (c) 2014 Rich Hodgkins. All rights reserved.
//

import UIKit
import XCTest

class RandomTests: XCTestCase {

    func testRandom() {
    
        for _ in (1...100) {
         
            let length = random() % 10000
            let randomData = secureRandomData(length)
            
            XCTAssertNotNil(randomData, "Data nil")
            XCTAssertEqual(randomData!.length, length, "Data incorrect length")
        }
    }
}
