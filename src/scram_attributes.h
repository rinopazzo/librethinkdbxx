#pragma once

#include <string>
#include <map>

namespace RethinkDB {
    class ScramAttributes{
        typedef void(ScramAttributes::*func)(const std::string&);
        
    private:
        std::map<std::string, func> attributeMap_;
        
        std::string authIdentity_;
        std::string username_;
        std::string nonce_;
        std::string headerAndChannelBinding_;
        std::string salt_;
        std::string iterationCount_;
        std::string clientProof_;
        std::string serverSignature_;
        std::string error_;
        std::string originalString_;
        
        void initAttributeMapping();
        void setAttribute(const std::string& key, const std::string& value);
        friend std::ostream& operator<<(std::ostream &strm, const ScramAttributes& a);
        
    public:
        ScramAttributes();
        //copy constructors
        ScramAttributes(ScramAttributes& other);
        ScramAttributes(std::string& input);
        
        void authIdentity(const std::string& authIdentity);
        void username(const std::string& username);
        void nonce(const std::string& nonce);
        void headerAndChannelBinding(const std::string& headerAndChannelBinding);
        void salt(const std::string& salt);
        void iterationCount(const std::string& iterationCount);
        void clientProof(const std::string& clientProof);
        void serverSignature(const std::string& serverSignature);
        void error(const std::string& error);
        
        const std::string& nonce() const;
        const std::string& salt() const;
        const std::string& iterationCount() const;
        const std::string& serverSignature() const;
        
        ~ScramAttributes();
    };
    
    inline std::ostream& operator<<(std::ostream &strm, const ScramAttributes& a){
        if(a.originalString_.length()){
            strm << a.originalString_;
        }
        else{
            bool isFirst=true;
            if(a.username_.length()){
                strm << std::string("n=")<<a.username_;
                isFirst=false;
            }
            if(a.nonce_.length()){
                strm << std::string((isFirst?"r=":",r=")) << a.nonce_;
                isFirst=false;
            }
            if(a.headerAndChannelBinding_.length()){
                strm << std::string((isFirst?"c=":",c=")) << a.headerAndChannelBinding_;
                isFirst=false;
            }
            if(a.clientProof_.length()){
                strm << std::string((isFirst?"p=":",p=")) <<a.clientProof_;
            }
        }
        return strm;
    }

}
