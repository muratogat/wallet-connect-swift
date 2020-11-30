// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import Starscream
import PromiseKit

public typealias SessionRequestClosure = (_ id: Int64, _ session: WCSession, _ peerParam: WCSessionRequestParam) -> Void
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

open class WCInteractor {
    public let bridgeURL: URL
    public private(set) var state: WCInteractorState
    public var sessions: [WCSession]
    
    let clientMeta = WCPeerMeta(name: "Aktionariat iOS App", url: "https://aktionariat.com")
    
    // incoming event handlers
    public var onSessionRequest: SessionRequestClosure?
    public var onDisconnect: DisconnectClosure?
    public var onError: ErrorClosure?
    public var onCustomRequest: CustomRequestClosure?
    public var onSign: EthSignClosure?
    public var onTransaction: EthTransactionClosure?

    // outgoing promise resolvers
    private var connectResolver: Resolver<Bool>?

    private let socket: WebSocket
    private var handshakeId: Int64 = -1
    private weak var pingTimer: Timer?
    private weak var keepAliveTimer: Timer?
    private weak var sessionTimer: Timer?
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
            return Promise.value(true)
        }
        socket.connect()
        state = .connecting
        return Promise<Bool> { [weak self] seal in
            self?.connectResolver = seal
        }
    }
    
    public func reconnectExistingSessions() {
        for session in WCSessionStore.getSessionsForBridge(url: bridgeURL) {
            print("Reconnection to existing session: " + session.topic)
            subscribeToSession(session: session)
        }
    }

    open func pause() {
        state = .paused
        socket.disconnect(forceTimeout: nil, closeCode: CloseCode.goingAway.rawValue)
    }

    open func resume() {
        socket.connect()
        state = .connecting
    }

    open func disconnect() {
        stopTimers()

        socket.disconnect()
        state = .disconnected

        connectResolver = nil
        handshakeId = -1

        // WCSessionStore.clear(session.topic)
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
                print("Found Session for matching clientID : " + session.clientId)
                return session
            }
        }
        return nil
    }
    
    open func approveSession(session: WCSession, accounts: [String], chainId: Int) -> Promise<Void> {
        guard handshakeId > 0 else {
            return Promise(error: WCError.sessionInvalid)
        }
        
        let result = WCApproveSessionResponse(approved: true,
                                              chainId: chainId,
                                              accounts: accounts,
                                              peerId: session.clientId,
                                              peerMeta: clientMeta)
        let response = JSONRPCResponse(id: handshakeId, result: result)
        return encryptAndSend(session: session, data: response.encoded)
    }

    open func rejectSession(session: WCSession, _ message: String = "Session Rejected") -> Promise<Void> {
        guard handshakeId > 0 else {
            return Promise(error: WCError.sessionInvalid)
        }
        let response = JSONRPCErrorResponse(id: handshakeId, error: JSONRPCError(code: -32000, message: message))
        return encryptAndSend(session: session, data: response.encoded)
    }

    open func killSession(session: WCSession) -> Promise<Void> {
        let result = WCSessionUpdateParam(approved: false, chainId: nil, accounts: nil)
        let response = JSONRPCRequest(id: generateId(), method: WCEvent.sessionUpdate.rawValue, params: [result])
        return encryptAndSend(session: session, data: response.encoded)
            .map { [weak self] in
                self?.disconnect()
            }
    }

    
    // Request handling. //
    
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
            sessionTimer?.invalidate()
            onSessionRequest?(request.id, session, params)
            
        case .sessionUpdate:
            // topic == clientId
            let request: JSONRPCRequest<[WCSessionUpdateParam]> = try event.decode(decrypted)
            guard let param = request.params.first else { throw WCError.badJSONRPCRequest }
            if param.approved == false {
                disconnect()
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
            
        default:
            break
        }
    }
    
    // Approves the received request with the appropriate payload
    // This is called after user confirmation
    // ethSign : expects signed message
    // ethSignTransaction: expects signed transaction
    // ethSendTransaction: expects txid of signed and sent transaction
    open func approveRequest<T: Codable>(id: Int64, session: WCSession, result: T) -> Promise<Void> {
        let response = JSONRPCResponse(id: id, result: result)
        return encryptAndSend(session: session, data: response.encoded)
    }

    open func rejectRequest(id: Int64, session: WCSession, message: String) -> Promise<Void> {
        let response = JSONRPCErrorResponse(id: id, error: JSONRPCError(code: -32000, message: message))
        return encryptAndSend(session: session, data: response.encoded)
    }
}

// MARK: internal funcs
extension WCInteractor {
    public func subscribe(topic: String) {
        let message = WCSocketMessage(topic: topic, type: .sub, payload: "")
        let data = try! JSONEncoder().encode(message)
        socket.write(data: data)
        WCLog("==> subscribe: \(String(data: data, encoding: .utf8)!)")
    }

    private func encryptAndSend(session: WCSession, data: Data) -> Promise<Void> {
        WCLog("==> encrypt: \(String(data: data, encoding: .utf8)!) ")
        let encoder = JSONEncoder()
        let payload = try! WCEncryptor.encrypt(data: data, with: session.key)
        let payloadString = encoder.encodeAsUTF8(payload)
        let message = WCSocketMessage(topic: session.peerId ?? session.topic, type: .pub, payload: payloadString)
        let data = message.encoded
        return Promise { seal in
            socket.write(data: data) {
                WCLog("==> sent \(String(data: data, encoding: .utf8)!) ")
                seal.fulfill(())
            }
        }
    }

    
    // Murat - Fully custom keep alive
    private func setupKeepAlive() {
        // Murat - Don't add more timers. Invalidate first if exists.
        if (pingTimer?.isValid ?? false) {
            pingTimer?.invalidate()
        }
        
        if (keepAliveTimer?.isValid ?? false) {
            keepAliveTimer?.invalidate()
        }
        
        keepAliveTimer = Timer.scheduledTimer(withTimeInterval: 131, repeats: true) { [weak socket] _ in
            WCLog("-- keepAlive ---")
            self.pause()
            self.resume()
        }
        
        pingTimer = Timer.scheduledTimer(withTimeInterval: 23, repeats: true) { [weak socket] _ in
            // WCLog("==> ping")
            socket?.write(ping: Data())
        }
    }

    /*
    private func connectExistingSessions() {
        // check if it's an existing session
        if let existing = WCSessionStore.load(session.topic), existing.session == session {
            peerId = existing.peerId
            peerMeta = existing.peerMeta
            return
        }

        // we only setup timer for new sessions
        sessionTimer = Timer.scheduledTimer(withTimeInterval: sessionRequestTimeout, repeats: false) { [weak self] _ in
            self?.onSessionRequestTimeout()
        }
    }
 */

    private func stopTimers() {
        pingTimer?.invalidate()
        keepAliveTimer?.invalidate()
        sessionTimer?.invalidate()
    }

    private func onSessionRequestTimeout() {
        onDisconnect(error: WCError.sessionRequestTimeout)
    }
}

// MARK: WebSocket event handler
extension WCInteractor {
    private func onConnect() {
        WCLog("<== websocketDidConnect")

        //setupPingTimer()
        setupKeepAlive()
        reconnectExistingSessions()

        connectResolver?.fulfill(true)
        connectResolver = nil

        state = .connected
    }

    private func onDisconnect(error: Error?) {
        WCLog("<== websocketDidDisconnect, error: \(error.debugDescription)")

        stopTimers()

        if let error = error {
            connectResolver?.reject(error)
        } else {
            connectResolver?.fulfill(false)
        }

        connectResolver = nil
        onDisconnect?(error)

        state = .disconnected
    }

    private func onReceiveMessage(text: String) {
        // handle ping in text format :(
        if text == "ping" { return socket.write(pong: Data()) }
        guard let (topic, payload) = WCEncryptionPayload.extract(text) else { return }
        WCLog("<== Received msg for topic: \(topic)")
        do {
            guard let session = getSessionByTopic(topic: topic) else {
                WCLog("No session found for topic: " + topic)
                return
            }
            
            let decrypted = try WCEncryptor.decrypt(payload: payload, with: session.key)
            
            guard let json = try JSONSerialization.jsonObject(with: decrypted, options: []) as? [String: Any] else {
                throw WCError.badJSONRPCRequest
            }
            
            // WCLog("<== Decrypted Successfully: \(String(data: decrypted, encoding: .utf8)!)")
            
            if let method = json["method"] as? String {
                WCLog("<== Decrypted Method: \(method)")
                if let event = WCEvent(rawValue: method) {
                    try handleEvent(event, session: session, decrypted: decrypted)
                } else if let id = json["id"] as? Int64 {
                    onCustomRequest?(id, json)
                }
            }
        } catch let error {
            onError?(error)
            WCLog("==> onReceiveMessage error: \(error.localizedDescription)")
        }
    }
}
