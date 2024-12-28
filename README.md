# semaphore-messenger
Semaphore Messenger is a secure end-to-end encrypted messaging client designed with security, flexibility, and API compatability in mind. Semaphore is written in C, utilizing the popular openssl library
for cryptographic power. Semaphore is currently in its very early stages, but is intended to be able to support various protocols and message types, including text messages, images, and hopefully video.

## Semaphore Protocol

The Semaphore Messenger uses the Semaphore protocol. The Semaphore protocol is a simpltic, lightweight messaging protocol that is relatively simple to integrate into external applications, with the goal being security, simplicity, and application.

### Message format

The Semaphore protocol consists of message formatted as follows
```
[TRANSMISSION START {4 bytes}] [MESSAGE SIZE {1 byte}] [RECIEVER ADDRESS (SHA256) {32 bytes}] [SENDER ADDRESS (SHA256) {32 bytes}] [TIMESTAMP {4 bytes}] [MESSAGE SIZE {4 bytes}] [MESSAGE CONTENT {MESSAGE SIZE}] [SIGNATURE LENGTH {4 bytes}] [SIGNATURE {SIGNATURE LENGTH}]
```

#### Transmission start

4  bytes. 

