// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import Starscream
import PromiseKit

public typealias SessionRequestClosure = (_ id: Int64, _ session: WCSession) -> Void
public typealias DisconnectClosure = (Error?) -> Void
public typealias CustomRequestClosure = (_ id: Int64, _ request: [String: Any]) -> Void
public typealias ErrorClosure = (Error) -> Void
public typealias EthSignClosure = (_ id: Int64, _ session: WCSession, _ payload: WCEthereumSignPayload) -> Void
public typealias EthTransactionClosure = (_ id: Int64, _ session: WCSession, _ event: WCEvent, _ transaction: WCEthereumTransaction) -> Void

public enum WCInteractorState {
    case connected
    case connecting
    case paused
    case disconnected
}

public class WCInteractor {
    public let bridgeURL: URL
    public private(set) var state: WCInteractorState
    public var sessions: [WCSession]
    
    let clientMeta = WCPeerMeta(name: "Aktionariat iOS App", url: "https://aktionariat.com")
    
    // incoming event handlers
    public var onSessionRequest: SessionRequestClosure?
    public var onSign: EthSignClosure?
    public var onTransaction: EthTransactionClosure?

    // outgoing promise resolvers
    private var connectResolver: Resolver<Bool>?

    private let socket: WebSocket
    private var handshakeId: Int64 = -1
    private weak var pingTimer: Timer?
    private let sessionRequestTimeout: TimeInterval = 20

    // Socket Init and Management
    public init(bridgeURL: URL) {
        self.bridgeURL = bridgeURL
        self.state = .disconnected
        self.sessions = []
        
        var request = URLRequest(url: bridgeURL)
        request.timeoutInterval = sessionRequestTimeout
        self.socket = WebSocket(request: request)

        socket.onConnect = { [weak self] in self?.onConnect() }
        socket.onDisconnect = { [weak self] error in self?.onDisconnect(error: error) }
        socket.onText = { [weak self] text in self?.onReceiveMessage(text: text) }
        socket.onPong = { _ in /* WCLog("<== pong") */ }
        socket.onData = { data in WCLog("<== websocketDidReceiveData: \(data.toHexString())") }
    }

    deinit {
        disconnect()
    }

    public func connect() -> Promise<Bool> {
        if socket.isConnected {
            // print("Connected")
            return Promise<Bool> { seal in
                seal.fulfill(true)
            }
        }
        socket.connect()
        state = .connecting
        return Promise<Bool> { [self] seal in
            self.connectResolver = seal
            print("Connecting")
        }
    }
    
    public func reconnectExistingSessions() {
        for session in WCSessionStore.getSessionsForBridge(url: bridgeURL) {
            print("Reconnection to existing session: " + session.topic)
            subscribeToSession(session: session)
        }
    }

    public func pause() {
        stopPing()
        
        state = .paused
        socket.disconnect(forceTimeout: nil, closeCode: CloseCode.goingAway.rawValue)
    }

    public func resume() {
        socket.connect()
        state = .connecting
    }

    public func disconnect() {        
        stopPing()
        
        socket.disconnect()
        state = .disconnected
        
        connectResolver = nil
        handshakeId = -1
    }
    
    // Connects a new session to this interactor. A session has both session.topic and clientId subscriptions.
    public func subscribeToSession(session: WCSession) {
        sessions.append(session)
        subscribe(topic: session.topic)
        subscribe(topic: session.clientId)
    }

    public func getSessionByTopic(topic: String) -> WCSession? {
        for session in sessions {
            if (topic == session.topic || topic == session.clientId) {
                // print("Found Session for matching clientID : " + session.clientId)
                return session
            }
        }
        return nil
    }
    
    public func approveSession(session: WCSession, accounts: [String], chainId: Int) {
        guard handshakeId > 0 else {
            WCLog("Invalid Session")
            return
        }
        
        let result = WCApproveSessionResponse(approved: true, chainId: chainId, accounts: accounts, peerId: session.clientId, peerMeta: clientMeta)
        let response = JSONRPCResponse(id: handshakeId, result: result)
        
        encryptAndSend(session: session, data: response.encoded).cauterize()
        
        WCSessionStore.store(session)
    }

    public func rejectSession(session: WCSession, _ message: String = "Session Rejected") {
        guard handshakeId > 0 else {
            WCLog("Invalid Session")
            return
        }
        
        let response = JSONRPCErrorResponse(id: handshakeId, error: JSONRPCError(code: -32000, message: message))
        encryptAndSend(session: session, data: response.encoded).cauterize()
    }

    public func disconnectSession(session: WCSession) {
        let result = WCSessionUpdateParam(approved: false, chainId: nil, accounts: nil)
        let response = JSONRPCRequest(id: generateId(), method: WCEvent.sessionUpdate.rawValue, params: [result])
        
        encryptAndSend(session: session, data: response.encoded).cauterize()
        
        // Remove from sessions
        if let index = self.sessions.firstIndex(of: session) {
            self.sessions.remove(at: index)
        }
        
        // Disconnect if no sessions left
        if self.sessions.count == 0 {
            self.disconnect()
        }
        
        WCSessionStore.clear(session.topic)
    }

    // Approves the received request with the appropriate payload
    // This is called after user confirmation
    // ethSign : expects signed message
    // ethSignTransaction: expects signed transaction
    // ethSendTransaction: expects txid of signed and sent transaction
    public func approveRequest<T: Codable>(id: Int64, session: WCSession, result: T) -> Promise<Void> {
        let response = JSONRPCResponse(id: id, result: result)
        return encryptAndSend(session: session, data: response.encoded)
    }

    public func rejectRequest(id: Int64, session: WCSession, message: String) -> Promise<Void> {
        let response = JSONRPCErrorResponse(id: id, error: JSONRPCError(code: -32000, message: message))
        return encryptAndSend(session: session, data: response.encoded)
    }
}

// MARK: internal funcs
extension WCInteractor {
    private func subscribe(topic: String) {
        let message = WCSocketMessage(topic: topic, type: .sub, payload: "")
        let data = try! JSONEncoder().encode(message)
        socket.write(data: data)
        // WCLog("==> subscribe: \(String(data: data, encoding: .utf8)!)")
    }
    
    private func ack(topic: String) {
        let message = WCSocketMessage(topic: topic, type: .ack, payload: "")
        let data = try! JSONEncoder().encode(message)
        socket.write(data: data)
        // print("Sent Ack");
    }

    private func encryptAndSend(session: WCSession, data: Data) -> Promise<Void> {
        // WCLog("==> Encrypt and Send: \(String(data: data, encoding: .utf8)!) ")
        let encoder = JSONEncoder()
        let payload = try! WCEncryptor.encrypt(data: data, with: session.key)
        let payloadString = encoder.encodeAsUTF8(payload)
        let message = WCSocketMessage(topic: session.peerId ?? session.topic, type: .pub, payload: payloadString)
        let data = message.encoded
        return Promise { seal in
            socket.write(data: data) {
                // WCLog("==> sent \(String(data: data, encoding: .utf8)!) ")
                seal.fulfill(())
            }
        }
    }

    // Murat - Custom keep-alive
    private func schedulePing() {
        // Murat - Don't add more timers. Invalidate first if exists.
        if (pingTimer?.isValid ?? false) {
            pingTimer?.invalidate()
        }
        
        pingTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak socket] _ in
            // WCLog("==> ping")
            socket?.write(ping: Data())
        }
    }

    private func stopPing() {
        pingTimer?.invalidate()
    }

    private func onSessionRequestTimeout() {
        onDisconnect(error: WCError.sessionRequestTimeout)
    }
}

// MARK: WebSocket event handler
extension WCInteractor {
    private func onConnect() {
        WCLog("<== websocketDidConnect")
        state = .connected
        
        reconnectExistingSessions()
        schedulePing()

        print(connectResolver != nil ? "YAY" : "NAY")
        
        connectResolver?.fulfill(true)
        connectResolver = nil
    }

    private func onDisconnect(error: Error?) {
        WCLog("<== websocketDidDisconnect, error: \(error.debugDescription)")

        stopPing()

        if let error = error {
            connectResolver?.reject(error)
        } else {
            connectResolver?.fulfill(false)
        }

        connectResolver = nil
        state = .disconnected
    }

    private func onReceiveMessage(text: String) {
        // Respond to ping
        if (text == "ping") {
            return socket.write(pong: Data())
        }
        
        // Respond to real messages with payload
        guard let (topic, payload) = WCEncryptionPayload.extract(text) else {
            WCLog("Can't get payload of message: " + text)
            return
        }
                
        guard let session = getSessionByTopic(topic: topic) else {
            WCLog("No session found for topic: " + topic)
            return
        }
        
        WCLog("<== Received msg for topic: \(topic) --- Peer: \(session.peerMeta?.url ?? "NOT SET YET")")
                
        do {
            let decrypted = try WCEncryptor.decrypt(payload: payload, with: session.key)
            
            guard let json = try JSONSerialization.jsonObject(with: decrypted, options: []) as? [String: Any] else {
                WCLog("Failed to deserialize payload.")
                return
            }
            
            // WCLog("<== Decrypted Successfully: \(String(data: decrypted, encoding: .utf8)!)")
            
            guard let method = json["method"] as? String else {
                WCLog("Failed to parse received method.")
                return
            }
            
            guard let event = WCEvent(rawValue: method) else {
                WCLog("Unknown received method.")
                return
            }
            
            // Ack this connection
            ack(topic: topic)
            
            // Wow we made it here. Everything was correctly formatted and decrypted.
            // Try handling it.
            try handleEvent(event, session: session, decrypted: decrypted)
        }
        catch let error {
            WCLog("==> onReceiveMessage error: \(error.localizedDescription)")
        }
    }
    
    // Handles the incoming message AFTER DECRYPTION
    // Decodes the decrypted message into Payload objects and triggers callbacks, if set
    // For example, showing the approval sheet to the user
    private func handleEvent(_ event: WCEvent, session: WCSession, decrypted: Data) throws {
        switch event {
        case .sessionRequest:
            // topic == session.topic
            let request: JSONRPCRequest<[WCSessionRequestParam]> = try event.decode(decrypted)
            guard let params = request.params.first else { throw WCError.badJSONRPCRequest }
            handshakeId = request.id
            session.peerId = params.peerId
            session.peerMeta = params.peerMeta
            onSessionRequest?(request.id, session)
            
        case .sessionUpdate:
            // topic == clientId
            let request: JSONRPCRequest<[WCSessionUpdateParam]> = try event.decode(decrypted)
            guard let param = request.params.first else { throw WCError.badJSONRPCRequest }
            if param.approved == false {
                disconnectSession(session: session)
            }
            
        case .ethSign, .ethPersonalSign:
            let request: JSONRPCRequest<[String]> = try event.decode(decrypted)
            let payload = try JSONDecoder().decode(WCEthereumSignPayload.self, from: decrypted)
            onSign?(request.id, session, payload)
            
        case .ethSignTypeData:
             let payload = try JSONDecoder().decode(WCEthereumSignPayload.self, from: decrypted)
             guard case .signTypeData(let id, _, _) = payload else {
                return
             }
             onSign?(id, session, payload)
            
        case .ethSendTransaction, .ethSignTransaction:
            let request: JSONRPCRequest<[WCEthereumTransaction]> = try event.decode(decrypted)
            guard !request.params.isEmpty else { throw WCError.badJSONRPCRequest }
            onTransaction?(request.id, session, event, request.params[0])
        }
    }
    
}
