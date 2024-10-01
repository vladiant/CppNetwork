# Linux Network Programming Tutorial

## Client socket call flow
```
socket()
connect()
while (x)
{
   write()
   read()
}
close()
```

## Server socket call flow
```
socket()
bind()
listen()
while (1)
{
   accept()
   while (x)
   {
      read()
      write()
   }
   close()
}
close()
```

## Server Algorithms

### Iterative Connection-Oriented (TCP)
```
create a socket
bind to a well-known port
place in passive mode
while (1)
{
   Accept the next connection
   while (client writes)
   {
      read a client request
      perform requested action
      send a reply
   }
   close the client socket
}
close the passive socket
```

### Concurrent Connection-Oriented (TCP)
```
create a socket
bind to a well-known port
use listen to place in passive mode
while (1)
{
   accept a client connection
   fork
   if (child)
   {
      communicate with new socket
      close new socket
      exit
   }
   else
   {
      close new socket
   }
}
```

### Iterative Connectionless (UDP)
```
create a socket
bind to a well-known port
while (1)
{
    read a request from some client
    send a reply to that client
}
```

### Concurrent Connectionless
```
create a socket
bind to a well-known port
while (1)
{
   read a request from some client
   fork
   if(child)
   {
      send a reply to that client
      exit
   }
}
```

### Concurrency Using a Single Process
```
create a socket
bind to a well-known port
while (1)
{
   use select to wait for I/O
   if(original socket is ready)
   {
      accept() a new connection and add to read list
   }
   else if (a socket is ready for read)
   {
      read data from a client
      if(data completes a request)
      {
         do the request
         if(reply needed)
         {
            add socket to write list
         }
      }
   }
   else if (a socket is ready for write)
   {
      write data to a client
      if(message is complete)
      {
         remove socket from write list
      }
      else
      {
         adjust write parameters and leave in write list
      }
   }
}
```

## References
* [The Tenouk's Linux Socket (network) programming tutorial](https://www.tenouk.com/cnlinuxsockettutorials.html)
