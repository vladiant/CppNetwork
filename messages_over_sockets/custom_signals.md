# Custom Command-Signals

## Protocol
`[Length][Cmd][Data]`

## Pseudo code - send
```cpp
enum MessageCodes{
    RegularMessage = 0,
    Disconnect,
    CreateRoom,
    JoinRoom,
    LeaveRoom,
    RenameRoom
};

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

    MessageCodes msg_code = static_cast<MessageCodes>(recved_msg[0]);
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