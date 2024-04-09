# JSON Messages

## Pseudo code - send
```cpp
#include "json.h"

enum MessageCodes{
    RegularMessage = 0,
    Disconnect,
    CreateRoom,
    JoinRoom,
    LeaveRoom,
    RenameRoom
};

void MessageTextToJSONtext(std::string& message_to_convert, MessageCodes msg_code){
    
    nlohmann::json agent_json_msg = {
        {"Type", static_cast<unsigned char>(msg_code)},
        {"Message", message_to_convert},
        {"Timestamp", GetTimestamp()}
    };

    message_to_convert = agent_json_msg.dump();
}

std::string Convert_JSON_data_to_string(const std::string& received_JSON_data){
    nlohmann::json received_JSON_data = nlohmann::json::parse(agent_message);
    std::string agent_code = received_JSON_data.at("AgentCode"s).dump();
    std::string timestamp = received_JSON_data.at("Timestamp"s).dump();
    std::string message = received_JSON_data.at("Message"s).dump();

    
}

int SendMessage(const std::string& message, MessageCodes command){
    unsigned char cmd_char = static_cast<unsigned char>(command);
    
    // Pseudo code
    std::string new_message = (message_length + 1) + cmd_char + message;

    // Send the message
    ...
}
```

## Pseudo code - receive
```cpp

int ReceiveMessage(char* writable_buffer){

    std::string recved_msg;
    // ... Receive the messaging code + data

    nlohmann::json received_JSON_data = nlohmann::json::parse(agent_message);

    MessageCodes msg_code = static_cast<MessageCodes>(received_JSON_data.at("Type"s).dump());

    std::string timestamp = received_JSON_data.at("Timestamp"s).dump();
    std::string message = received_JSON_data.at("Message"s).dump();


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

## References
* <https://github.com/nlohmann/json>