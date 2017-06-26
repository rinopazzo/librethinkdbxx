#pragma once

#include "crypto.h"
#include <stdlib.h>
#include "scram_attributes.h"

#define DATA_MAX_SIZE 1024
#define NONCE_BYTES 18

namespace RethinkDB {
    
    /*ProtocolState*/
    class ProtocolState{
        
    public:
        virtual ProtocolState* allocNextState(const std::string& response) = 0;
        virtual bool toSend(unsigned char* data, int32_t* lenght) = 0;
        virtual bool isFinished() = 0;
        virtual ~ProtocolState() {};
    };
    
    /*InitialState class*/
    class InitialState : public ProtocolState{
        
    private:
        std::string nonce_;
        std::string username_;
        int32_t passwordLen_;
        unsigned char* password_;
        
    public:
        InitialState(const std::string& username, const std::string& password);
        ~InitialState();
        
        virtual ProtocolState* allocNextState(const std::string& response);
        virtual bool toSend(unsigned char* data, int32_t* lenght);
        virtual bool isFinished();
    };
    
    /*WaitingForProtocolRange*/
    class WaitingForProtocolRange : public ProtocolState{
        
    private:
        std::string nonce_;
        std::string username_;
        unsigned char* password_;
        int32_t passwordLen_;
        ScramAttributes clientFirstMessage_;
        unsigned char* message_;
        int32_t messageLen_;
                
    public:
        WaitingForProtocolRange(const std::string& nonce, const std::string& username, const unsigned char* password, int32_t passwordLen, ScramAttributes& clientFirstMessage, const unsigned char* message, int32_t messageLen);
        ~WaitingForProtocolRange();
        
        virtual ProtocolState* allocNextState(const std::string& response);
        virtual bool toSend(unsigned char* data, int32_t* lenght);
        virtual bool isFinished();
    };
    
    /*WaitingForAuthResponse*/
    
    class WaitForAuthResponse : public ProtocolState{
    private:
        std::string nonce_;
        unsigned char* password_;
        int32_t passwordLen_;
        ScramAttributes clientFirstMessage_;
        
    public:
        WaitForAuthResponse(const std::string& nonce, const unsigned char* password, int32_t passwordLen, ScramAttributes& clientFirstMessage);
        ~WaitForAuthResponse();
        
        virtual ProtocolState* allocNextState(const std::string& response);
        virtual bool toSend(unsigned char* data, int32_t* lenght);
        virtual bool isFinished();
    };
    
    /*WaitingForAuthSuccess*/
    
    class WaitingForAuthSuccess : public ProtocolState{
    private:
        unsigned char* serverSignature_;
        int32_t serverSignatureLen_;
        unsigned char* message_;
        int32_t messageLen_;
        
    public:
        WaitingForAuthSuccess(const unsigned char* serverSignaturem, int32_t serverSignatureLen, const unsigned char* message, int32_t messageLen);
        ~WaitingForAuthSuccess();
        
        virtual ProtocolState* allocNextState(const std::string& response);
        virtual bool toSend(unsigned char* data, int32_t* lenght);
        virtual bool isFinished();
    };
    
    /*HandshakeSuccess*/
    class HandshakeSuccess : public ProtocolState{
    public:
        HandshakeSuccess();
        virtual ProtocolState* allocNextState(const std::string& response);
        virtual bool toSend(unsigned char* data, int32_t* lenght);
        virtual bool isFinished();
    };
    
    /*Handshake class*/
    class Handshake{
        
    private:
        std::string username_;
        std::string password_;
        ProtocolState* state_;
        
    public:
        Handshake(const std::string& username, const std::string& password);
        void reset();
        bool nextMessage(unsigned char* data, int32_t* lenght, const std::string& response="");
        bool isFinished();
        ~Handshake();
    };
}
