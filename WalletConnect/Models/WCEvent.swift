// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public enum WCEvent: String {
    case sessionRequest = "wc_sessionRequest"
    case sessionUpdate = "wc_sessionUpdate"

    case ethSign = "eth_sign"
    case ethPersonalSign = "personal_sign"
    case ethSignTypeData = "eth_signTypedData"

    case ethSignTransaction = "eth_signTransaction"
    case ethSendTransaction = "eth_sendTransaction"
}

extension WCEvent {
    static let eth = Set<WCEvent>([.ethSign, .ethPersonalSign, .ethSignTypeData, .ethSignTransaction, .ethSendTransaction])

    func decode<T: Codable>(_ data: Data) throws -> JSONRPCRequest<T> {
        return try JSONDecoder().decode(JSONRPCRequest<T>.self, from: data)
    }
}
