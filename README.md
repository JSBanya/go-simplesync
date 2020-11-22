# go-simplesync

## Compile

```
make fetch
make
```

## Initial setup

Edit config.json to contain the information needed to run. Important fields to modify are:

"folder": This is the local folder to synchronize with peers. This may be a different folder than the one on remote machines. Will recursively add and watch sub-directories.

"password": The password that will be required by peers in order to connect to your machine.

##### For each peer (may be zero or more):

"peers" > "IP": The IP of a peer to connect to.

"peers" > "password": The password for the peer in order to connect to their machine.

## Behavior Overview

On startup, the program will attempt connections to all peers listed in the config file indefinitely. Upon successful connection, an initial synchronization occurs that creates files that exist locally but do not exist on the peer, and updates out-of-date files that do exist both locally and on the peer (determined by last modified time).

All directories and files will then be watched as long as the program is running, transmitting any file creation, updates, and deletions that must be replicated on the peer.

## Disclaimer

Not intended for serious production use. This program was only designed to serve as a quick workaround for synchronizing or sharing files over a network without the need for more dedicated solutions.
