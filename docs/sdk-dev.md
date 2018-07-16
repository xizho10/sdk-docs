
# sdk dev



content：
* [dev](#dev)
	* [1. http rpc](#1-http-rpc)
	* [2. wallet](#2-wallet)
	* [3. asset](#3-asset)
	* [4. identity](#3-identity)

## 1. http rpc

>rpc: 
https://github.com/ontio/ontology/blob/master/docs/specifications/rpc_api.md


java code example:

https://github.com/ontio/ontology-java-sdk/blob/master/src/main/java/com/github/ontio/sdk/manager/ConnectMgr.java

need complete:

get transaction

get smartcontract

get smartcontract event

get block

get block height

send transaction

## 2. wallet

>wallet https://github.com/ontio/ontology-ts-sdk/blob/master/docs/en/Wallet_File_Specification.md 

1.account: add update get delete

2.identity: add update get delete

>account https://github.com/ontio-community/specifications/blob/master/sdk_dev_standard/en/account.md

1.Generation Public and Private Key Pair with ECDSA

2.Generate a public key based on the specified private key with ECDSA

3.export WIF

4.Private key encryption and decryption with GCM, dont need CTR

5.ECDSA signature

6.ECDSA verify signature

java code example:

https://github.com/ontio/ontology-java-sdk/blob/master/src/main/java/com/github/ontio/account/Account.java

## 3. asset

>native asset include ont and ong.

https://github.com/ontio/ontology-java-sdk/blob/master/docs/en/asset.md

java code example:

https://github.com/ontio/ontology-java-sdk/blob/master/src/main/java/com/github/ontio/smartcontract/nativevm/Ong.java

https://github.com/ontio/ontology-java-sdk/blob/master/src/main/java/com/github/ontio/smartcontract/nativevm/Ont.java

need complete:

1. String sendTransfer(Account sendAcct, String recvAddr, long amount, Account payerAcct, long gaslimit, long gasprice)

2. long queryBalanceOf(String address)

3. String unboundOng(String address)

4. String withdrawOng(Account sendAcct, String toAddr, long amount, Account payerAcct, long gaslimit, long gasprice)

>nep-5 smartcontract digit asset:

don't need do this

## 4. identity

> identity rigistry and get ddo
 https://github.com/ontio/ontology-java-sdk/blob/master/docs/en/identity_claim.md

java code example:

https://github.com/ontio/ontology-java-sdk/blob/master/src/main/java/com/github/ontio/smartcontract/nativevm/OntId.java

need complete:

String sendRegister(Identity ident, String password, Account payerAcct, long gaslimit, long gasprice) 

String sendGetDDO(String ontid)
