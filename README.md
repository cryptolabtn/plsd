# Public Ledger for Sensitive Data

This repo contains a GO implementation of the protocol [Public Ledger for Sensitive Data](https://arxiv.org/abs/1906.06912).

To run the protocol, make the file ```private_ledger``` executable:
```
sudo chmod +x private_ledger
```
and then run it providing the path to settings file:
```
./private_ledger -settings InsertPathToSettings
```

or just:
```
./private_ledger
```

if you want to run it with the default settings file: ```test/settings.txt```.


The settings file contains the following configurations:
- padsize;
- shards number;
- shardsFile;
- keysfile;
- root path;
- encryptPath.

The default settings configuration is the following:
```
64
5000
test/shards.enc
test/keys.enc
test/block
test/ct
```
