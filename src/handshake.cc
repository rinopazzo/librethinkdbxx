#include "handshake.h"

#include "protocol_defs.h"
#include "crypto.h"
#include "error.h"
#include "rapidjson/document.h"
#include <sstream>

using namespace RethinkDB;
using namespace rapidjson;

const uint32_t version_magic = static_cast<uint32_t>(Protocol::VersionDummy::Version::V1_0);
//const uint32_t json_magic = static_cast<uint32_t>(Protocol::VersionDummy::Protocol::JSON);

const std::string client_key("Client Key");
const std::string server_key("Server Key");

/* InitialState class */

bool isSuccess(Document& document){
    GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator>> value;
    return (document.HasMember("success") && (value=document["success"]).IsBool() &&value.GetBool());
}

InitialState::InitialState(const std::string& username, const std::string& password) : username_(username){
    if(password.length()){
        password_ = (unsigned char*)malloc((password.size() + 1) * sizeof(unsigned char));
        memset(password_, 0, (password.size() + 1));
        memcpy(password_, password.data(), password.size());
        passwordLen_ = (int32_t)password.size();
    }
    char nonce[64];
    memset(nonce, 0, 64);
    Crypto::make_nonce(nonce, NONCE_BYTES);
    nonce_ = std::string(nonce);
}

ProtocolState* InitialState::allocNextState(const std::string& response){
    if(!response.length()){
        ScramAttributes clientFirstMessage;
        clientFirstMessage.username(username_);
        clientFirstMessage.nonce(nonce_);
        
        std::stringstream ss;
        ss << "{";
        ss << "\"protocol_version\":0,";
        ss << "\"authentication_method\":\"SCRAM-SHA-256\",";
        ss << "\"authentication\":" << "\"n,," << clientFirstMessage << "\"";
        ss << "}";
        
        int32_t versionLen, jsonLen;
        int32_t len = (versionLen=sizeof(version_magic)) + (jsonLen=(int32_t)ss.str().size());
        unsigned char* msg = (unsigned char*)malloc((len+1) * sizeof(char));
        memcpy(msg, &version_magic, versionLen);
        memcpy(msg + versionLen, ss.str().data(), jsonLen);
        msg[len] = 0;
        ProtocolState* state = new WaitingForProtocolRange(nonce_, username_, password_, passwordLen_, clientFirstMessage, msg, len);
        free(msg);
        return state;
    }
    return NULL;
}

bool InitialState::toSend(unsigned char* data, int32_t* lenght){
    return false;
}

bool InitialState::isFinished(){
    return false;
}

InitialState::~InitialState(){
    free(password_);
}

/* WaitingForProtocolRange class*/

WaitingForProtocolRange::WaitingForProtocolRange(const std::string& nonce, const std::string& username, const unsigned char* password, int32_t passwordLen, ScramAttributes& clientFirstMessage, const unsigned char* message, int32_t messageLen)
: nonce_(nonce), username_(username), clientFirstMessage_(clientFirstMessage){
    password_ = (unsigned char*)malloc((passwordLen+1) * sizeof(unsigned char));
    memcpy(password_, password, passwordLen);
    password_[passwordLen] = 0;
    passwordLen_ = passwordLen;
    message_ = (unsigned char*)malloc((messageLen+1) * sizeof(unsigned char));
    memcpy(message_, message, messageLen);
    message_[messageLen] = 0;
    messageLen_ = messageLen;
}

ProtocolState* WaitingForProtocolRange::allocNextState(const std::string& response){
    Document document;
    document.Parse(response.c_str());
    if(isSuccess(document)){
        GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator>> minValue;
        GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator>> maxValue;
        if(document.HasMember("min_protocol_version") && (minValue=document["min_protocol_version"]).IsInt() &&
           document.HasMember("max_protocol_version") && (maxValue=document["max_protocol_version"]).IsInt()){
            if(minValue.GetInt() > 0 || maxValue.GetInt() < 0){
                throw Error("Unsupported protocol version: %s", response.c_str());
            }
        }
        return new WaitForAuthResponse(nonce_, password_, passwordLen_, clientFirstMessage_);;
    }
    else{
        throw Error("Server rejected connection with message: %s", response.c_str());
    }
    return NULL;
}
bool WaitingForProtocolRange::toSend(unsigned char* data, int32_t* lenght){
    memcpy(data, message_, messageLen_);
    *lenght = (messageLen_+1);
    return true;
}
bool WaitingForProtocolRange::isFinished(){
    return false;
}

WaitingForProtocolRange::~WaitingForProtocolRange(){
    free(password_);
    free(message_);
}

/* WaitingForAuthResponse class*/

WaitForAuthResponse::WaitForAuthResponse(const std::string& nonce, const unsigned char* password, int32_t passwordLen, ScramAttributes& clientFirstMessage)
: nonce_(nonce), clientFirstMessage_(clientFirstMessage){
    password_ = (unsigned char*)malloc((passwordLen+1) * sizeof(unsigned char));
    memcpy(password_, password, passwordLen);
    password_[passwordLen] = 0;
    passwordLen_ = passwordLen;
}

ProtocolState* WaitForAuthResponse::allocNextState(const std::string& response){
    Document document;
    document.Parse(response.c_str());
    GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator>> value;
    if(isSuccess(document) && document.HasMember("authentication") && (value=document["authentication"]).IsString()){
        std::string serverFirstMessage = value.GetString();
        ScramAttributes serverAuth(serverFirstMessage);
        if(serverAuth.nonce().compare(0, nonce_.length(), nonce_)!=0){
            throw Error("Server rejected connection with message: %s", response.c_str());
        }
        
        ScramAttributes clientFinalMessageWithoutProof;
        clientFinalMessageWithoutProof.headerAndChannelBinding("biws");
        clientFinalMessageWithoutProof.nonce(serverAuth.nonce());
        
        //Salted password = Hi(Normalize(password), salt, i)

        unsigned char* salt = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(salt, 0, DATA_MAX_SIZE);
        int32_t saltLen = Crypto::unbase64(serverAuth.salt().c_str(), (int32_t)serverAuth.salt().length(), salt);
        
        unsigned char* saltedPassword = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(saltedPassword, 0, DATA_MAX_SIZE);
        int count = atoi(serverAuth.iterationCount().c_str());
        int32_t saltedPasswordLen = Crypto::pbkdf2((const char*)password_, salt, saltLen, count, saltedPassword);
        
        //Client key = HMAC(saltedPassword, "Client Key")
        unsigned char* clientKey = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(clientKey, 0, DATA_MAX_SIZE);
        int32_t clientKeyLen = Crypto::hmac_sha256(saltedPassword, saltedPasswordLen, (unsigned char*)client_key.data(), (int32_t)client_key.size(), clientKey);
        
        unsigned char* storedKey = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(storedKey, 0, DATA_MAX_SIZE);
        int32_t storedKeyLen = Crypto::sha256(clientKey, clientKeyLen, storedKey);
        
        std::stringstream authSS;
        authSS << clientFirstMessage_;
        authSS << ",";
        authSS << serverFirstMessage;
        authSS << ",";
        authSS << clientFinalMessageWithoutProof;
        std::string authMessage(authSS.str());
        
        unsigned char* clientSignature = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(clientSignature, 0, DATA_MAX_SIZE);
        int32_t clientSignatureLen = Crypto::hmac_sha256(storedKey, storedKeyLen, (unsigned char*)authMessage.data(), (int32_t)authMessage.size(), clientSignature);
        
        unsigned char* clientProof = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(clientProof, 0, DATA_MAX_SIZE);
        int32_t clientProofLen = Crypto::x_or(clientKey, clientKeyLen, clientSignature, clientSignatureLen, clientProof);
        
        unsigned char* serverKey = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(serverKey, 0, DATA_MAX_SIZE);
        int32_t serverKeyLen = Crypto::hmac_sha256(saltedPassword, saltedPasswordLen, (unsigned char*)server_key.data(), (int32_t)server_key.size(), serverKey);
        
        unsigned char* serverSignature = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(serverSignature, 0, DATA_MAX_SIZE);
        int32_t serverSignatureLen = Crypto::hmac_sha256(serverKey, serverKeyLen, (unsigned char*)authMessage.data(), (int32_t)authMessage.size(), serverSignature);
        
        char* clientProofBase64 = (char*)malloc(DATA_MAX_SIZE * sizeof(char));
        memset(clientProofBase64, 0, DATA_MAX_SIZE);
        Crypto::base64(clientProof, clientProofLen, clientProofBase64);
        
        clientFinalMessageWithoutProof.clientProof(std::string(clientProofBase64));
        std::stringstream ss;
        ss << "{";
        ss << "\"authentication\":\"" << clientFinalMessageWithoutProof << "\"";
        ss << "}";
        int32_t jsonLen;
        int32_t len = jsonLen=(int32_t)ss.str().size();
        unsigned char* msg = (unsigned char*)malloc((len+1) * sizeof(char));
        memcpy(msg, ss.str().data(), jsonLen);
        msg[len] = 0;
        ProtocolState* state = new WaitingForAuthSuccess(serverSignature, serverSignatureLen, msg, len);
        free(salt);
        free(saltedPassword);
        free(clientKey);
        free(storedKey);
        free(clientSignature);
        free(clientProof);
        free(serverKey);
        free(serverSignature);
        free(clientProofBase64);
        free(msg);
        return state;
    }
    else{
        throw Error("Server rejected connection with message: %s", response.c_str());
    }
    return NULL;
}
bool WaitForAuthResponse::toSend(unsigned char* data, int32_t* lenght){
    return false;
}
bool WaitForAuthResponse::isFinished(){
    return false;
}

WaitForAuthResponse::~WaitForAuthResponse(){
    free(password_);
}

/* WatingForAuthSuccess */

WaitingForAuthSuccess::WaitingForAuthSuccess(const unsigned char* serverSignature, int32_t serverSignatureLen, const unsigned char* message, int32_t messageLen){
    serverSignature_ = (unsigned char*)malloc((serverSignatureLen+1)*sizeof(unsigned char));
    memcpy(serverSignature_, serverSignature, serverSignatureLen);
    serverSignature_[serverSignatureLen] = 0;
    serverSignatureLen_ = serverSignatureLen;
    message_ = (unsigned char*)malloc((messageLen+1) * sizeof(unsigned char));
    memcpy(message_, message, messageLen);
    message_[messageLen] = 0;
    messageLen_ = messageLen;
}

ProtocolState* WaitingForAuthSuccess::allocNextState(const std::string& response){
    Document document;
    document.Parse(response.c_str());
    GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator>> value;
    if(isSuccess(document) && document.HasMember("authentication") && (value=document["authentication"]).IsString()){
        std::string serverSecondMessage = value.GetString();
        ScramAttributes auth(serverSecondMessage);
        
        unsigned char* serverSignature = (unsigned char*)malloc(DATA_MAX_SIZE * sizeof(unsigned char));
        memset(serverSignature, 0, DATA_MAX_SIZE);
        int32_t len = Crypto::unbase64(auth.serverSignature().c_str(), (int32_t)auth.serverSignature().length(), serverSignature);
        int result = memcmp(serverSignature_, serverSignature, len);
        free(serverSignature);
        if(result){
            //failed
            throw Error("Server rejected connection with message: %s", response.c_str());
        }
    }
    else{
        throw Error("Server rejected connection with message: %s", response.c_str());
    }
    return new HandshakeSuccess();
}

bool WaitingForAuthSuccess::toSend(unsigned char* data, int32_t* lenght){
    memcpy(data, message_, messageLen_);
    *lenght = (messageLen_+1);
    return true;
}

bool WaitingForAuthSuccess::isFinished(){
    return false;
}

WaitingForAuthSuccess::~WaitingForAuthSuccess(){
    free(serverSignature_);
    free(message_);
}

/*HandshakeSuccess*/

HandshakeSuccess::HandshakeSuccess(){
    
}

ProtocolState* HandshakeSuccess::allocNextState(const std::string& response){
    return NULL;
}

bool HandshakeSuccess::toSend(unsigned char* data, int32_t* lenght){
    return false;
}
bool HandshakeSuccess::isFinished(){
    return true;
}

/* Handshake class*/

Handshake::Handshake(const std::string& username, const std::string& password) : username_(username), password_(password){
    state_ = new InitialState(username, password);
}

void Handshake::reset(){
    delete(state_);
    state_ = new InitialState(username_, password_);
}
bool Handshake::nextMessage(unsigned char* data, int32_t* lenght, const std::string& response){
    ProtocolState* nextState = state_->allocNextState(response);
    delete(state_);
    state_ = nextState;
    return nextState->toSend(data, lenght);
}

bool Handshake::isFinished(){
    return state_->isFinished();
}

Handshake::~Handshake(){
    delete(state_);
}
