## 交易所使用指南

* 1 获得ontSdk实例
```
String ip = "http://127.0.0.1";
String restUrl = ip + ":" + "20334";
String rpcUrl = ip + ":" + "20386";
String wsUrl = ip + ":" + "20385";
OntSdk ontSdk = OntSdk.getInstance();
ontSdk.setRpc(rpcUrl);
ontSdk.setRestful(restUrl);
ontSdk.setDefaultConnect(wm.getRestful());
```

* 2 将私钥转换成字节数组

```
byte[] privateKey = Helper.hexToBytes(privatekey1)
```

* 3 利用私钥创建Account

```
com.github.ontio.account.Account acct1 = new com.github.ontio.account.Account(privateKey, ontSdk.keyType, ontSdk.curveParaSpec);
```
参数说明：
privateKey 私钥
ontSdk.keyType 加密算法，这里使用的是ECDSA
ontSdk.curveParaSpec ECDSA加密曲线类型

* 4 根据公钥获得账户地址Address

获得单个公钥的地址
```
Address address = addressFromPubKey("120203a4e50edc1e59979442b83f327030a56bffd08c2de3e0a404cefb4ed2cc04ca3e");
```
参数说明：序列化后的公钥

获得多个公钥的地址
```
Address recvAddr = Address.addressFromMultiPubKeys(M, publicKey1, publicKey2,publicKey3);
```
参数说明：
M 需要签名的公钥的数量(要小于或等于后面公钥的数量)
publicKey1,publicKey2,publicKey3  序列化后的公钥

* 4 转账

state 数据结构

```
public class State implements Serializable {
    public byte version;
    public Address from;
    public Address to;
    public BigInteger value;
    ...
    }
```

state封装的是版本号，发送方地址，接收方地址，转移的数量

Transfers 数据结构
```
public class Transfers implements Serializable {
    public byte version = 0;
    public State[] states;
    ...
    }
```
tranfers封装的是多个state，即一次可以向多个账户转移资产

Contract 数据结构
```
public class Contract implements Serializable {
    public byte version;
    public byte[] code = new byte[0];
    public Address constracHash;
    public String method;
    public byte[] args;
    ...
    }
```

contract封装的是版本号，合约代码，合约codeAddress，方法名，参数


基本流程：
    构造交易参数
    构造交易对象
    签名（发送方要对交易签名，当发送方是多个或者有多签地址时，如何签名请看下面例子）
    序列化交易对象
    发送交易

例一 发送方是根据单个公钥获得的地址
```
State state = new State(senderAddr, recvAddr, new BigInteger(String.valueOf(amount)));
Transfers transfers = new Transfers(new State[]{state});
Contract contract = new Contract((byte) 0, null, Address.parse(ontContractAddr), "transfer", transfers.toArray());
Fee[] fees = new Fee[1];
fees[0] = new Fee(0, sender);
Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(ontContractAddr, null, contract.toArray(), VmType.Native.value(), fees);
ontSdk.signTx(tx, new com.github.ontio.account.Account[][]{{acct0}});
ontSdk.getConnectMgr().sendRawTransaction(tx.toHexString());
```

例二 发送方是根据多个公钥获得的地址

```
Address multiAddr = Address.addressFromMultiPubKeys(2, acct1.serializePublicKey(), acct2.serializePublicKey());
Address recvAddr = acct5.getAddressU160();
int amount = 10;

State state = new State(multiAddr, recvAddr, new BigInteger(String.valueOf(amount)));
Transfers transfers = new Transfers(new State[]{state});
Contract contract = new Contract((byte) 0, null, Address.parse(ontContractAddr), "transfer", transfers.toArray());
Fee[] fees = new Fee[1];
fees[0] = new Fee(0, multiAddr);
Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(ontContractAddr, null, contract.toArray(), VmType.Native.value(), fees);
ontSdk.signTx(tx, new com.github.ontio.account.Account[][]{{acct1, acct2}});
ontSdk.getConnectMgr().sendRawTransaction(tx.toHexString());
```

例三 发送方是多个，一个是根据单个公钥获得的地址，另一个是根据多个公钥获得的地址

```
Address sender1 = acct0.getAddressU160();
Address sender2 = Address.addressFromMultiPubKeys(2, acct1.serializePublicKey(), acct2.serializePublicKey());
Address recvAddr = acct5.getAddressU160();

int amount = 10;
int amount2 = 20;
State state = new State(sender1, recvAddr, new BigInteger(String.valueOf(amount)));
State state2 = new State(sender2, recvAddr, new BigInteger(String.valueOf(amount2)));

Transfers transfers = new Transfers(new State[]{state, state2});
Contract contract = new Contract((byte) 0, null, Address.parse(ontContractAddr), "transfer", transfers.toArray());
Fee[] fees = new Fee[2];
fees[0] = new Fee(0, sender1);
fees[1] = new Fee(0, sender2);
Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(ontContractAddr, null, contract.toArray(), VmType.Native.value(), fees);
ontSdk.signTx(tx, new com.github.ontio.account.Account[][]{{acct0}, {acct1, acct2}});
ontSdk.getConnectMgr().sendRawTransaction(tx.toHexString());
```



