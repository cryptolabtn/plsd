# Public Ledger for Sensitive Data

This repo contains a GO implementation of the protocol [Public Ledger for Sensitive Data](https://arxiv.org/abs/1906.06912).

To run the protocol, change the permission of the file ```private_ledger```:
```
sudo chmod -x private_ledger
```
and then run it:
```
./private_ledger -path InsertPathTofile
```
If you do not provide the path in input it will load the default file: ```docs/private-ledger.pdf```
