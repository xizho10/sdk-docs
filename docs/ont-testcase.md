
## 账号

* 公私钥对生成
* 公钥序列号
* 私钥序列化
* 签名验签

## 核心组件

*	区块正反序列化

*	Transfer正反序列化

* TransferFrom正反序列化

* 智能合约脚本创建

* 智能合约Opcode表

* 交易正反序列化

* deploy交易payload正反序列化

* invoke交易payload正反序列化

*	http,rpc和websocket接口

http,rpc和websocket接口

```
 Object sendRawTransaction(boolean preExec,String userid,String hexData)
 Object sendRawTransaction(String hexData)
 Transaction getRawTransaction(String txhash)
 Object getRawTransactionJson(String txhash)
 int getGenerateBlockTime()
 int getNodeCount()
 int getBlockHeight()
 Block getBlock(int height)
 Block getBlock(String hash)
 Object getBlockJson(int height)
 Object getBlockJson(String hash)
 Object getBalance(String address)
 Object getContract(String hash)
 Object getContractJson(String hash)
 Object getSmartCodeEvent(int height)
 Object getSmartCodeEvent(String hash)
 int getBlockHeightByTxHash(String hash)
 String getStorage(String codehash,String key) t
 Object getMerkleProof(String hash)
```

## 接口

* 智能合约Abi测试
* claim测试
  参考ClaimDemo
* ECIES加解密测试
	参考ECIESDemo
* ont资产交易测试
  参考OntAssetDemo
* ontid测试
  参考OntIdDemoTestpublic
```
Identity sendRegister(String password)
public String sendAddPubKey(String ontid, String password, String newpubkey)
public String sendGetPublicKeyId(String ontid,String password)
public String sendGetPublicKeyStatus(String ontid,String password,byte[] pkId)
public String sendRemovePubKey(String ontid, String password, String removepk)
public String sendUpdateAttribute(String ontid, String password, byte[] path, byte[] type, byte[] value)
public String sendRemoveAttribute(String ontid, String password, byte[] path)
public String sendAddRecovery(String ontid, String password, String recoveryScriptHash)
private Map parseDdoData(String ontid, String obj)
public String sendGetDDO(String ontid)
public String createOntIdClaim(String signerOntid,String password, String context, Map<String, Object> claimMap, Map metaData)
public boolean verifyOntIdClaim(String claim)
public Object getProof(String txhash)
public boolean verifyMerkleProof(String claim)
```
* 存证测试

```
 public String sendPut(String addr,String password,String key,String value)
 public String sendGet(String addr,String password,String key)
```

* 智能合约测试

```
public String sendInvokeSmartCode(String ontid, String password, AbiFunction abiFunction, byte vmtype)
public Transaction invokeTransaction(String ontid, String password, AbiFunction abiFunction, byte vmtype)
DeployCodeTransaction
createCodeParamsScript
buildWasmContractJsonParam
makeDeployCodeTransaction
makeInvokeCodeTransaction
```

* 钱包管理测试
  AccountDemo等
* 钱包json文件测试
	AccountDemo等
* connect管理测试
  参考Demo
