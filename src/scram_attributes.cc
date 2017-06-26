#include "scram_attributes.h"

using namespace RethinkDB;

void ScramAttributes::authIdentity(const std::string& authIdentity){
    authIdentity_ = authIdentity;
}

void ScramAttributes::username(const std::string& username){
    username_ = username;
}

void ScramAttributes::nonce(const std::string& nonce){
    nonce_ = nonce;
}

const std::string& ScramAttributes::nonce() const{
    return nonce_;
}

void ScramAttributes::headerAndChannelBinding(const std::string& headerAndChannelBinding){
    headerAndChannelBinding_ = headerAndChannelBinding;
}

void ScramAttributes::salt(const std::string& salt){
    salt_ = salt;
}

const std::string& ScramAttributes::salt() const{
    return salt_;
}

void ScramAttributes::iterationCount(const std::string& iterationCount){
    iterationCount_ = iterationCount;
}

const std::string& ScramAttributes::iterationCount() const{
    return iterationCount_;
}

void ScramAttributes::clientProof(const std::string& clientProof){
    clientProof_ = clientProof;
}

void ScramAttributes::serverSignature(const std::string& serverSignature){
    serverSignature_ = serverSignature;
}

const std::string& ScramAttributes::serverSignature() const{
    return serverSignature_;
}

void ScramAttributes::error(const std::string& error){
    error_ = error;
}

void ScramAttributes::initAttributeMapping(){
    attributeMap_.insert(std::pair<std::string, func>("a",&ScramAttributes::authIdentity));
    attributeMap_.insert(std::pair<std::string, func>("n",&ScramAttributes::username));
    attributeMap_.insert(std::pair<std::string, func>("r",&ScramAttributes::nonce));
    attributeMap_.insert(std::pair<std::string, func>("c",&ScramAttributes::headerAndChannelBinding));
    attributeMap_.insert(std::pair<std::string, func>("s",&ScramAttributes::salt));
    attributeMap_.insert(std::pair<std::string, func>("i",&ScramAttributes::iterationCount));
    attributeMap_.insert(std::pair<std::string, func>("p",&ScramAttributes::clientProof));
    attributeMap_.insert(std::pair<std::string, func>("v",&ScramAttributes::serverSignature));
    attributeMap_.insert(std::pair<std::string, func>("e",&ScramAttributes::error));

}

void ScramAttributes::setAttribute(const std::string& key, const std::string& value){
    std::map<std::string, func>::iterator find = attributeMap_.find(key);
    if(find != attributeMap_.end()){
        (this->*find->second)(value);
    }
}

ScramAttributes::ScramAttributes(){
    initAttributeMapping();
}

ScramAttributes::ScramAttributes(ScramAttributes& other)  :
    authIdentity_(other.authIdentity_),
    username_(other.username_),
    nonce_(other.nonce_),
    headerAndChannelBinding_(other.headerAndChannelBinding_),
    salt_(other.salt_),
    iterationCount_(other.iterationCount_),
    clientProof_(other.clientProof_),
    serverSignature_(other.serverSignature_),
    error_(other.error_),
    originalString_(other.originalString_){
        initAttributeMapping();
}

ScramAttributes::ScramAttributes(std::string& input) : originalString_(input){
    initAttributeMapping();
    std::size_t start = 0, end = 0;
    while ((end = input.find(',', start)) != std::string::npos || (start<(end=input.length()))) {
        std::size_t keyEnd;
        std::string token(input.substr(start, end - start));
        if((keyEnd = token.find('=',0)) != std::string::npos && token.length()>(keyEnd+1)){
            std::string key(token.substr(0, keyEnd));
            std::string value(token.substr(keyEnd + 1, token.length()-keyEnd));
            setAttribute(key, value);
        }
        start = end+1;
    }
}

ScramAttributes::~ScramAttributes(){
    
}


