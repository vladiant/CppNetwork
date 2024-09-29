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

## References
* [The Tenouk's Linux Socket (network) programming tutorial](https://www.tenouk.com/cnlinuxsockettutorials.html)
