# Bitcoin transaction signer

This is a server / client Perl application which is designed to create and sign
bitcoin transactions (pretty) securely. It is all a custom hack, as there isn't
PSBT format support in Bitcoin::Crypto (yet).

Server instance keeps the mnemonic phrase in its config (remember to `chmod
0600`!). It does not keep the password.

Client instance reads XML scripts and provides transaction details to the
server, asking for the signatures. It also asks for password for the mnemonic,
if any.

The idea is setup as follows:
- get a Raspberry PI or any other computer capable of running Perl
- disable WiFi, sshd, put on a firewall, never connect to the Internet
- set a static IP for the ethernet interface
- write mnemonic phrase onto the machine
- make it auto-run the server part of this application

And then, when the signatures are required:
- install client part of this application on any computer
- connect both machines with an ethernet cable, create a private network between them
- point the client at the static IP of the other machine
- create client scripts and run `script/signer sign`
- disconnect the ethernet cable

The client script asks for two passwords: system one and mnemonic one. Mnemonic
password is required to properly derive a master key from mnemonic phrase.
System password is a security measure in case the "hot" machine is compromised
or has some kind of malware.

Basically, every request to the server is checksummed. System password is a
part of this checksum, but is not sent openly (unlike mnemonic password). This
means the attacker must crack either system password + mnemonic password or
server + mnemonic password to get access to the coins. If your server
machine doesn't get stolen and you disconnect it from the client machine as
soon as possible, the risk should be negligible.

Still, I don't recommend anyone using this. Treat is as a fun research project
and buy a proper trusted hardware wallet to store your coins, which should be
in Raspberry PI price range anyway.

