# Protobuf Signals

## Buffer Definition
```
syntax = "proto3";

message Message {
  string timestamp = 1;
  string message = 2;
  string type = 3;
}
```

## Pseudo code - send
```cpp
#include "message_signature.pb.h"

enum MessageCodes{
    RegularMessage = 0,
    Disconnect,
    CreateRoom,
    JoinRoom,
    LeaveRoom,
    RenameRoom
};

int SerializeMessage(std::string& sending_message, MessageCodes msg_code){
    
    Message packed_msg;
  
    packed_msg.set_type(std::to_string(static_cast<unsigned char>(msg_code)));
    packed_msg.set_timestamp(GetTimeStamp());
    packed_msg.set_message(sending_message);

    std::string packed_str = packed_msg.SerializeToString();

    return 0;
}

int DeserializeMessage(const std::string& recved_msg, Message& msg_struct){
    Message deser_msg;
    if (deser_msg.ParseFromString(recved_msg)){
        return 0;
    }
  
    return -1; // failed to deserialize the message
}

int SendMessage(const std::string& message, MessageCodes command){
  
    // Pseudo code
    std::string new_message;
    SerializeMessage(new_message, command);

    // Send the message
    ...
}
```

## Pseudo code - receive
```cpp
int ReceiveMessage(char* writable_buffer){

    std::string recved_msg;
  
    // ... Receive the messaging code + data

    Message deser_msg;
    if (DeserializeMessage(recved_msg, deser_msg) == -1){
        std::cerr << "[Error] ReceiveMessage(): failed to deserialize a received message." << std::endl;
        return -1;
    }

    std::string timestamp = deser_msg.timestamp();
    std::string message = deser_msg.message();
    MessageCodes msg_code;
    try{
        msg_code = static_cast<MessageCodes>(deser_msg.type().at(0));      
    } catch(const std::exception& exc){ // deser_msg.type field is empty
        std::cerr << "[Error] ReceiveMessage(): Failed to parse the message code of the packet." << std::endl;
        return -1;
    }

    switch (msg_code){
        case MessageCodes::RegularMessage:
            // Handle the client sending a message
            break;

        case MessageCodes::Disconnect:
            // Handle the client wanting to disconnect from the server
            break;

        case MessageCodes::CreateRoom:
            // Handle the client wanting to create a new room.
            break;
        
        ...

        default:
            // Handle incorrect message code
    }

    ...
}
```