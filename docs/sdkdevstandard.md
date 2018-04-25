# SDK 开发文档
* [1. 密码学相关](#1.密码学相关)
 * [1.1 公私钥对生成](#1.1公私钥对生成)
 * [1.2 账户地址生成方案](#1.2账户地址生成方案)
* [2. 构造交易](#2构造交易)
 * [2.1 Neo合约构造交易](#2.1Neo合约构造交易)
 * [2.2 Wasm合约构造交易](#2.2Wasm合约构造交易)
* [3. 构造交易](#3与链通信)
 * [3.1 基础接口](#3.1基础接口)
 * [3.2 错误码](#3.2错误码)
* [4 智能合约使用说明](#4智能合约使用说明)
 * [4.1 部署和余额](#4.1部署和余额)
 * [4.2 调用合约](#4.2调用合约)
  * [4.2.1 Neo合约调用](#4.2.1Neo合约调用)
  * [4.2.2 Wasm合约调用](#4.2.2Wasm合约调用)
* [5. 原生合约使用说明](#5.原生合约使用说明)
 * [5.1 ont和ong资产转移](#5.1ont和ong资产转移)
 * [5.2 数字身份](#5.2数字身份)
 * [5.3 数字存证](#5.3数字存证)
* [附件](#附件)

## 1. 密码学相关

### 1.1 公私钥对生成
目前Ontology支持的算法

| ID | Algorithm |
|:--|:--|
|0x12|ECDSA|
|0x13|SM2|
|0x14|EdDSA|

ONT可签名方案说明( with 前面是散列算法，后面是签名算法)，支持的signature schemes：
```
SHA224withECDSA
SHA256withECDSA
SHA384withECDSA
SHA512withECDSA
SHA3-224withECDSA
SHA3-256withECDSA
SHA3-384withECDSA
SHA3-512withECDSA
RIPEMD160withECDSA
SM3withSM2
SHA512withEdDSA
```

公私钥和签名的序列化方法请参考https://github.com/ontio/ontology-crypto/wiki/ECDSA

* java获得公私钥对的示例

方法一：
```
public Account(KeyType type, Object... params) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator gen;
        AlgorithmParameterSpec paramSpec;
        switch (type) {
            case ECDSA:
            case SM2:
                if (!(params[0] instanceof String)) {
                    throw new Exception("invalid params");
                }
                String curveName = (String)params[0];
                paramSpec = new ECGenParameterSpec(curveName);
                this.param = Curve.valueOf(ECNamedCurveTable.getParameterSpec(curveName).getCurve());
                gen = KeyPairGenerator.getInstance("EC", "BC");
                break;
            default:
                //should not reach here
                throw new Exception("unsupported key type");
        }
        gen.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.type = type;
        this.addressU160 = Address.toScriptHash(serializePublicKey());
    }
```
方法二：
```
//生成私钥
byte[] privateKey = ECC.generateKey();
//根据私钥生成公钥
public Account(byte[] data, KeyType type, Object... params) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        switch (type) {
            case ECDSA:
            case SM2:
                BigInteger d = new BigInteger(1, data);
                ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec((String)params[0]);
                ECParameterSpec paramSpec = new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
                ECPrivateKeySpec priSpec = new ECPrivateKeySpec(d, paramSpec);
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                this.privateKey = kf.generatePrivate(priSpec);

                org.bouncycastle.math.ec.ECPoint Q = spec.getG().multiply(d).normalize();
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(
                        new ECPoint(Q.getAffineXCoord().toBigInteger(), Q.getAffineYCoord().toBigInteger()),
                        paramSpec);
                this.publicKey = kf.generatePublic(pubSpec);
                this.type = type;
                this.addressU160 = Address.toScriptHash(serializePublicKey());
                break;
            default:
                throw new Exception("unknown key type");
        }
    }
```
方法三：

```
//根据公钥获得Account，
private void parsePublicKey(byte[] publickey) throws Exception {
        if (data == null) {
            throw new Exception("null input");
        }
        if (data.length < 2) {
            throw new Exception("invalid data");
        }
        this.param = null;
        this.privateKey = null;
        this.publicKey = null;
        this.type = KeyType.fromLabel(data[0]);
        switch (this.type) {
            case ECDSA:
            case SM2:
                Curve c = Curve.fromLabel(data[1]);
                ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(c.toString());
                ECParameterSpec param = new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(
                        ECPointUtil.decodePoint(
                                param.getCurve(),
                                Arrays.copyOfRange(data, 2, data.length)),
                        param);
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                this.publicKey = kf.generatePublic(pubSpec);
                break;
            default:
                throw new Exception("unknown public key type");
        }
    }
```

### 1.2 账户地址生成方案

```
对于普通账户	： address = 0x01 + dhash160(pubkey)[1:]
对于多重签名账户：涉及三个量 n, m, pubkeys.
n为总公钥数，pubkeys为公钥的列表，m为需要的签名数量, 沿用Neo对多重签名的限制： n<=24
依次序列化n，m，和pubkeys 得到byte数组 multi_pubkeys
address = 0x02 + dhash160(multi-pubkeys)[1:]


对于合约账户				： address = CodeType + dhash160(code)[1:]
neovm 类合约				： address = 0x80 + dhash160(code)[1:]
wasm 类合约				： address = 0x90 + dhash160(code)[1:]
后续其他vm类型合约也可以向后面拓展.
```
交易在验签时根据地址前缀识别对应的签名算法，进行验签。 交易在执行时根据地址前缀识别对应的虚拟机类型，启动对应的vm运行合约。
示例：
```
//根据公钥计算的address
public static Address addressFromPubKey(byte[] publicKey) {
      try {
          byte[] bys = Digest.hash160(publicKey);
          bys[0] = 0x01;
          Address u160 = new Address(bys);
          return u160;
      } catch (Exception e) {
          throw new UnsupportedOperationException(e);
      }
  }
  public static Address addressFromPubKey(ECPoint publicKey) {
        try (ByteArrayOutputStream ms = new ByteArrayOutputStream()) {
            try (BinaryWriter writer = new BinaryWriter(ms)) {
                writer.writeVarBytes(Helper.removePrevZero(publicKey.getXCoord().toBigInteger().toByteArray()));
                writer.writeVarBytes(Helper.removePrevZero(publicKey.getYCoord().toBigInteger().toByteArray()));
                writer.flush();
                byte[] bys = Digest.hash160(ms.toByteArray());
                bys[0] = 0x01;
                Address u160 = new Address(bys);
                return u160;
            }
        } catch (IOException ex) {
            throw new UnsupportedOperationException(ex);
        }
    }
    //根据多重公钥计算address
  public static Address addressFromMultiPubKeys(int m, ECPoint... publicKeys) {
        if(m<=0 || m > publicKeys.length || publicKeys.length > 24){
            throw new IllegalArgumentException();
        }
        try (ByteArrayOutputStream ms = new ByteArrayOutputStream()) {
            try (BinaryWriter writer = new BinaryWriter(ms)) {
                writer.writeByte((byte)publicKeys.length);
                writer.writeByte((byte)m);
                ECPoint[] ecPoint = Arrays.stream(publicKeys).sorted((o1, o2) -> {
                    if (o1.getXCoord().toString().compareTo(o2.getXCoord().toString()) <= 0) {
                        return -1;
                    }
                    return 1;
                }).toArray(ECPoint[]::new);
                for(ECPoint publicKey:ecPoint) {
                    writer.writeVarBytes(Helper.removePrevZero(publicKey.getXCoord().toBigInteger().toByteArray()));
                    writer.writeVarBytes(Helper.removePrevZero(publicKey.getYCoord().toBigInteger().toByteArray()));
                }
                writer.flush();
                byte[] bys = Digest.hash160(ms.toByteArray());
                bys[0] = 0x02;
                Address u160 = new Address(bys);
                return u160;
            }
        } catch (IOException ex) {
            throw new UnsupportedOperationException(ex);
        }
    }
    //根据合约hex和虚拟机类型获得智能合约的address
    public static String getCodeAddress(String codeHexStr,byte vmtype){
        Address code = Address.toScriptHash(Helper.hexToBytes(codeHexStr));
        byte[] hash = code.toArray();
        hash[0] = vmtype;
        String codeHash = Helper.toHexString(hash);
        return codeHash;
    }
```

## 2 构造交易

目前Ontology链上可以运行Native、NEO和WASM合约，SDK要实现NEO和WASM合约的部署和调用交易。

* Transaction类字段如下

```
public abstract class Transaction extends Inventory {
    public byte version = 0;
    public final TransactionType txType;
    public int nonce = new Random().nextInt();
    public Attribute[] attributes;
    public Fee[] fee = new Fee[0];
    public long networkFee;
    public Sig[] sigs = new Sig[0];
  }
```
* 虚拟机类型

```
Native(0xff),
NEOVM(0x80),
WASMVM(0x90);
```

### 2.1 Neo合约构造交易
1. 读取合约abi文件

```
InputStream is = new FileInputStream("C:\\ZX\\IdContract.abi.json");
byte[] bys = new byte[is.available()];
is.read(bys);
is.close();
String abi = new String(bys);
AbiInfo abiinfo = JSON.parseObject(abi, AbiInfo.class);
```
2. 构造参数

   将函数参数转换成虚拟机可以执行的字节码，详细的字节码数据请查看本文当末尾。
   假设调用某合约中函数需要如下信息：
   函数名，参数1，参数2
   转换成虚拟机能够识别的字节码：
   * 将参数放入list集合中
   ```
   list.add(函数名);
   tempList.add(参数1);
   tempList.add(参数2);
   list.add(tempList);
   ```
   * 反序遍历list集合
     如果遇到list集合，将list集合中的数据反序遍历并压入栈中，然后将该list集合的大小压入栈中，sb.pushPack();

   * 将参数压入栈中进行的操作（以Java中的数据类型为例）
     如果参数是boolean类型数据。

     ```
     //true对应的字节码是0x51,false对应的字节码是0x00
     public ScriptBuilder push(boolean b) {
        if(b == true) {
            return add(ScriptOp.OP_1);
        }
        return add(ScriptOp.OP_0);
    }
     ```

     如果参数是BigInteger

     ```
     public ScriptBuilder push(BigInteger number) {
       //判断是不是-1
   		if (number.equals(BigInteger.ONE.negate())) {
            return add(ScriptOp.OP_1NEGATE);
        }
        //判断是不是0
   		if (number.equals(BigInteger.ZERO)) {
            return add(ScriptOp.OP_0);
        }
        //判断是不是大于0并且小于等于16
   		if (number.compareTo(BigInteger.ZERO) > 0 && number.compareTo(BigInteger.valueOf(16)) <= 0) {
            return add((byte) (ScriptOp.OP_1.getByte() - 1 + number.byteValue()));
        }
        return push(number.toByteArray());
    }
     ```

     如果参数是byte数组

     ```
     public ScriptBuilder push(byte[] data) {
        if (data == null) {
        	throw new NullPointerException();
        }
        if (data.length <= (int)ScriptOp.OP_PUSHBYTES75.getByte()) {
            ms.write((byte)data.length);
            ms.write(data, 0, data.length);
        } else if (data.length < 0x100) {
            add(ScriptOp.OP_PUSHDATA1);
            ms.write((byte)data.length);
            ms.write(data, 0, data.length);
        } else if (data.length < 0x10000) {
            add(ScriptOp.OP_PUSHDATA2);
   		ms.write(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short)data.length).array(), 0, 2);
            ms.write(data, 0, data.length);
        } else if (data.length < 0x100000000L) {
            add(ScriptOp.OP_PUSHDATA4);
            ms.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(data.length).array(), 0, 4);
            ms.write(data, 0, data.length);
        } else {
            throw new IllegalArgumentException();
        }
        return this;
    }
     ```
* Java转换参数的示例：
```
byte[] params = createCodeParamsScript(list);
public byte[] createCodeParamsScript(List<Object> list) {
ScriptBuilder sb = new ScriptBuilder();
try {
    for (int i = list.size() - 1; i >= 0; i--) {
        Object val = list.get(i);
        if (val instanceof byte[]) {
            sb.push((byte[]) val);
        } else if (val instanceof Boolean) {
            sb.push((Boolean) val);
        } else if (val instanceof Integer) {
            sb.push(new BigInteger(Int2Bytes_LittleEndian((int)val)));
        } else if (val instanceof List) {
            List tmp = (List) val;
            createCodeParamsScript(sb, tmp);
            sb.push(new BigInteger(String.valueOf(tmp.size())));
            sb.pushPack();
        } else {
        }
    }
} catch (Exception e) {
    e.printStackTrace();
}
return sb.toArray();
}
```

3. 构造交易

```
//根据虚拟机类型构造交易
if(vmtype == VmType.NEOVM.value()) {
   Contract contract = new Contract((byte) 0, null, Address.parse(codeAddr), "", params);
   params = Helper.addBytes(new byte[]{0x67}, contract.toArray());
}else if(vmtype == VmType.WASMVM.value()) {
    Contract contract = new Contract((byte) 1, null, Address.parse(codeAddr), method, params);
    params = contract.toArray();
}
InvokeCode tx = new InvokeCode();
tx.attributes = new Attribute[1];
tx.attributes[0] = new Attribute();
tx.attributes[0].usage = AttributeUsage.Nonce;
tx.attributes[0].data = UUID.randomUUID().toString().getBytes();
tx.code = params;
tx.gasLimit = 0;
tx.vmType = vmtype;
tx.fee = fees;
//Contract构造方法
public Contract(byte version,byte[] code,Address constracHash, String method,byte[] args){
    this.version = version;
    if (code != null) {
        this.code = code;
    }
    this.constracHash = constracHash;
    this.method = method;
    this.args = args;
}

```
4. 交易签名
```
//将交易对象中的字段值转换成字节数组txBytes
ByteArrayOutputStream ms = new ByteArrayOutputStream();
BinaryWriter writer = new BinaryWriter(ms);
writer.writeByte(version);
writer.writeByte(txType.value());
writer.writeInt(nonce);
serializeExclusiveData(writer);
writer.writeSerializableArray(attributes);
writer.writeSerializableArray(fee);
writer.writeLong(networkFee);
writer.flush();
byte[] txBytes = ms.toByteArray();
//对交易字节数组进行两次sha256
String txhash = Digest.sha256(Digest.sha256(txBytes))
//对txhash做签名
byte[] signature = tx.sign(accounts[i][j], getWalletMgr().getSignatureScheme());
//给Transaction中的字段赋值
tx.sigs = sigs;
//交易签名结构体如下
public class Sig implements Serializable {
    public byte[][] pubKeys = null;
    public int M;
    public byte[][] sigData;
 }
```

* 签名示例：

```
public Transaction signTx(Transaction tx, Account[][] accounts) throws Exception{
  Sig[] sigs = new Sig[accounts.length];
  for (int i = 0; i < accounts.length; i++) {
      sigs[i] = new Sig();
      sigs[i].pubKeys = new byte[accounts[i].length][];
      sigs[i].sigData = new byte[accounts[i].length][];
      for (int j = 0; j < accounts[i].length; j++) {
          sigs[i].M++;
          byte[] signature = tx.sign(accounts[i][j], getWalletMgr().getSignatureScheme());
          sigs[i].pubKeys[j] = accounts[i][j].serializePublicKey();
          sigs[i].sigData[j] = signature;
      }
  }
  tx.sigs = sigs;
  return tx;
}
```

5. 发送交易
  1. 将交易实例转换成字节数组
  txBytes
  ```
  byte[] txBytes = toArray();
  default byte[] toArray() {
        try (ByteArrayOutputStream ms = new ByteArrayOutputStream()) {
	        try (BinaryWriter writer = new BinaryWriter(ms)) {
	            serialize(writer);
	            writer.flush();
	            return ms.toByteArray();
	        }
        } catch (IOException ex) {
			throw new UnsupportedOperationException(ex);
		}
    }
  ```
  2. 将txBytes转换成十六进制字符串
  ```
  String txHex = toHexString(txBytes);
  public static String toHexString(byte[] value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            int v = Byte.toUnsignedInt(b);
            sb.append(Integer.toHexString(v >>> 4));
            sb.append(Integer.toHexString(v & 0x0f));
        }
        return sb.toString();
    }
  ```
  3. 发送交易(以restful为例)

```
public String sendTransaction(boolean preExec, String userid, String action, String version, String data) throws RestfulException {
        Map<String, String> params = new HashMap<String, String>();
        if (userid != null) {
            params.put("userid", userid);
        }
        if (preExec) {
            params.put("preExec", "1");
        }
        Map<String, Object> body = new HashMap<String, Object>();
        body.put("Action", action);
        body.put("Version", version);
        body.put("Data", data);
        try {
            return http.post(url + UrlConsts.Url_send_transaction, params, body);
        } catch (Exception e) {
            throw new RestfulException("Invalid url:" + url + "," + e.getMessage(), e);
        }
    }
```

### 2.2 Wasm合约构造交易

  1. 构造调用合约中的方法需要的参数；

     描述
  ```
  //交合约函数中需要的参数转换成虚拟机能够运行的字节码
  public String buildWasmContractJsonParam(Object[] objs) {
        List params = new ArrayList();
        for (int i = 0; i < objs.length; i++) {
            Object val = objs[i];
            if (val instanceof String) {
                Map map = new HashMap();
                map.put("type","string");
                map.put("value",val);
                params.add(map);
            } else if (val instanceof Integer) {
                Map map = new HashMap();
                map.put("type","int");
                map.put("value",String.valueOf(val));
                params.add(map);
            } else if (val instanceof Long) {
                Map map = new HashMap();
                map.put("type","int64");
                map.put("value",String.valueOf(val));
                params.add(map);
            } else if (val instanceof int[]) {
                Map map = new HashMap();
                map.put("type","int_array");
                map.put("value",val);
                params.add(map);
            } else if (val instanceof long[]) {
                Map map = new HashMap();
                map.put("type","int_array");
                map.put("value",val);
                params.add(map);
            } else {
                continue;
            }
        }
        Map result = new HashMap();
        result.put("Params",params);
        return JSON.toJSONString(result);
    }
  ```
  2. 构造交易；
  ```
  //需要的参数：合约hash，合约函数名，虚拟机类型，费用实例
  Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(codeAddress,"add",params.getBytes(),VmType.WASMVM.value(),new Fee[0]);
  ```
  3. 交易签名(如果是预执行不需要签名)；
    和Neo合约中一样

* 示例：

```
//设置要调用的合约地址codeAddress
ontSdk.getSmartcodeTx().setCodeAddress(codeAddress);
String funcName = "add";
//构造合约函数需要的参数
String params = ontSdk.getSmartcodeTx().buildWasmContractJsonParam(new Object[]{20,30});
//指定虚拟机类型构造交易
Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(ontSdk.getSmartcodeTx().getCodeAddress(),funcName,params.getBytes(),VmType.WASMVM.value(),new Fee[0]);
//发送交易
ontSdk.getConnectMgr().sendRawTransaction(tx.toHexString());

```

## 3 与链通信

Onotology链支持Restful、RPC和Websocket连接。
|  连接方式    | 端口  |
|:--------    |:--   |
|   restful   | 20334|
|   rpc       | 20336|
|   websocket | 20335|

### 3.1 基础接口

* boolean      sendRawTransaction(Transaction tx)
> Note: 参数是交易实例

* boolean      sendRawTransaction(String hexData)
> Note: 参数是交易实例的十六进制字符串形式

* Object       sendRawTransactionPreExec(String hexData)
> Note: 预执行不会修改链上的数据，不用参与共识

* Transaction  getTransaction(String txhash)
> Note: 参数是交易hash

* Object       getTransactionJson(String txhash)
> Note: 参数是交易hash

* int          getGenerateBlockTime()
> Note: 返回出块时间

* int          getNodeCount()
> Note: 返回区块链节点数

* int          getBlockHeight()
> Note: 返回区块高度

* Block        getBlock(int height)
> Note: 根据区块高度获得区块

* Block        getBlock(String hash)
> Note: 根据区块hash获得区块

* Object       getBalance(String address)
> Note: 根据账户address获得余额

* Object       getBlockJson(int height)
> Note: 根据区块高度获得区块数据的JSON格式数据

* Object       getBlockJson(String hash)
> Note: 根据区块hash获得区块数据的JSON格式数据

* Object       getContract(String hash)
> Note: 根据合约hash获得合约代码

* Object       getContractJson(String hash)
> Note: 根据合约hash获得合约代码

* Object       getSmartCodeEvent(int height)
> Note: 根据区块高度获得合约事件

* Object       getSmartCodeEvent(String hash)
> Note: 根据区块高度获得合约事件

* int          getBlockHeightByTxHash(String hash)
> Note: 根据区块hash获得区块高度

* String       getStorage(String codehash, String key)
> Note: codeHash是部署的合约的codeAddress,key要使用十六进制字符串

* Object       getMerkleProof(String txhash)
> Note: 获得交易hash的Merkle证明，证明该交易存在链上

### 3.2 错误码


| 返回代码 | 描述信息 | 说明 |
| :---- | ----------------------------- | ----------------- |
| 0 | SUCCESS | 成功 |
| 41001 | SESSION_EXPIRED | 会话无效或已过期（ 需要重新登录） |
| 41002 | SERVICE_CEILING | 达到服务上限 |
| 41003 | ILLEGAL_DATAFORMAT | 不合法数据格式 |
| 41004 | INVALID_VERSION| 不合法的版本 |
| 42001 | INVALID_METHOD | 无效的方法 |
| 42002 | INVALID_PARAMS | 无效的参数 |
| 43001 | INVALID_TRANSACTION | 无效的交易 |
| 43002 | INVALID_ASSET | 无效的资产 |
| 43003 | INVALID_BLOCK | 无效的块 |
| 44001 | UNKNOWN_TRANSACTION | 找不到交易 |
| 44002 | UNKNOWN_ASSET | 找不到资产 |
| 44003 | UNKNOWN_BLOCK | 找不到块 |
| 44004 | UNKNWN_CONTRACT | 找不到合约 |
| 45001 | INTERNAL_ERROR | 内部错误 |
| 47001 | SMARTCODE_ERROR| 智能合约错误 |

## 4 智能合约使用说明

### 4.1 部署合约

> Note: Neo和Wasm合约的部署一样。
* java 例子

```
InputStream is = new FileInputStream("IdContract.avm");
byte[] bys = new byte[is.available()];
is.read(bys);
is.close();
//将字节数组转换成十六进制字符串
code = Helper.toHexString(bys);
ontSdk.setCodeAddress(Helper.getCodeAddress(code,VmType.NEOVM.value()));
//部署合约
String txhash = ontSdk.getSmartcodeTx().makeDeployCodeTransaction(code, true, "name", "1.0", "1", "1", "1", VmType.NEOVM.value());
System.out.println("txhash:" + txhash);
//等待出块
Thread.sleep(6000);
DeployCodeTransaction t = (DeployCodeTransaction) ontSdk.getConnectMgr().getTransaction(txhash);
```
* 构造部署交易参数说明

| 参数      | 字段   | 类型  | 描述 |             说明 |
| ----- | ------- | ------ | ------------- | ----------- |
| 输入参数 | codeHexStr| String | 合约code十六进制字符串 | 必选 |
|        | needStorage    | Boolean | 是否需要存储   | 必选 |
|        | name    | String  | 名字       | 必选|
|        | codeVersion   | String | 版本       |  必选 |
|        | author   | String | 作者     | 必选 |
|        | email   | String | emal     | 必选 |
|        | desp   | String | 描述信息     | 必选 |
|        | VmType   | byte | 虚拟机类型     | 必选 |
| 输出参数 | tx   | Transaction  | 交易实例  |  |

### 4.2 调用合约

#### 4.2.1 Neo合约调用

 * 基本流程：
 1. 读取智能合约的abi文件；
 2. 构造调用智能合约函数；
 3. 构造交易；
 4. 交易签名(预执行不需要签名)；
 5. 发送交易。

 * 示例
 ```
 //读取智能合约的abi文件
 InputStream is = new FileInputStream("C:\\ZX\\NeoContract1.abi.json");
 byte[] bys = new byte[is.available()];
 is.read(bys);
 is.close();
 String abi = new String(bys);

 //解析abi文件
 AbiInfo abiinfo = JSON.parseObject(abi, AbiInfo.class);
 System.out.println("codeHash:"+abiinfo.getHash());
 System.out.println("Entrypoint:"+abiinfo.getEntrypoint());
 System.out.println("Functions:"+abiinfo.getFunctions());
 System.out.println("Events"+abiinfo.getEvents());

 //设置智能合约codeAddress
 ontSdk.setCodeAddress(abiinfo.getHash());

 //获取账号信息
 Identity did = ontSdk.getWalletMgr().getIdentitys().get(0);
 AccountInfo info = ontSdk.getWalletMgr().getAccountInfo(did.ontid,"passwordtest");

 //构造智能合约函数
 AbiFunction func = abiinfo.getFunction("AddAttribute");
 System.out.println(func.getParameters());
 func.setParamsValue(did.ontid.getBytes(),"key".getBytes(),"bytes".getBytes(),"values02".getBytes(),Helper.hexToBytes(info.pubkey));
 System.out.println(func);
 //调用智能合约，sendInvokeSmartCodeWithSign方法封装好了构造交易，签名交易，发送交易步骤
 String hash = ontSdk.getSmartcodeTx().sendInvokeSmartCodeWithSign(did.ontid, "passwordtest", func, (byte) VmType.NEOVM.value()););
 ```
 * AbiInfo结构(NEO合约调用的时候需要，WASM合约不需要)

```
public class AbiInfo {
    public String hash;
    public String entrypoint;
    public List<AbiFunction> functions;
    public List<AbiEvent> events;
}
public class AbiFunction {
    public String name;
    public String returntype;
    public List<Parameter> parameters;
}
public class Parameter {
    public String name;
    public String type;
    public String value;
}
```
#### 4.2.2 WASM合约调用
* 基本流程：
  1. 构造调用合约中的方法需要的参数；
  2. 构造交易；
  3. 交易签名(如果是预执行不需要签名)；
  4. 发送交易。

* 示例：

```
//设置要调用的合约地址codeAddress
ontSdk.getSmartcodeTx().setCodeAddress(codeAddress);
String funcName = "add";
//构造合约函数需要的参数
String params = ontSdk.getSmartcodeTx().buildWasmContractJsonParam(new Object[]{20,30});
//指定虚拟机类型构造交易
Transaction tx = ontSdk.getSmartcodeTx().makeInvokeCodeTransaction(ontSdk.getSmartcodeTx().getCodeAddress(),funcName,params.getBytes(),VmType.WASMVM.value(),new Fee[0]);
//发送交易
ontSdk.getConnectMgr().sendRawTransaction(tx.toHexString());
```

### 4.3 智能合约执行过程推送

创建websocket线程，解析推送结果。


* 1. 设置websocket链接


```
//lock 全局变量,同步锁
public static Object lock = new Object();

//获得ont实例
String ip = "http://127.0.0.1";
String wsUrl = ip + ":" + "20335";
OntSdk wm = OntSdk.getInstance();
wm.setWesocket(wsUrl, lock);
wm.setDefaultConnect(wm.getWebSocket());
wm.openWalletFile("OntAssetDemo.json");

```


* 2. 启动websocket线程


```
//false 表示不打印回调函数信息
ontSdk.getWebSocket().startWebsocketThread(false);

```

* 3. 启动结果处理线程


```
Thread thread = new Thread(
                    new Runnable() {
                        @Override
                        public void run() {
                            waitResult(lock);
                        }
                    });
            thread.start();
            //将MsgQueue中的数据取出打印
            public static void waitResult(Object lock) {
                    try {
                        synchronized (lock) {
                            while (true) {
                                lock.wait();
                                for (String e : MsgQueue.getResultSet()) {
                                    System.out.println("RECV: " + e);
                                    Result rt = JSON.parseObject(e, Result.class);
                                    //TODO
                                    MsgQueue.removeResult(e);
                                    if (rt.Action.equals("getblockbyheight")) {
                                        Block bb = Serializable.from(Helper.hexToBytes((String) rt.Result), Block.class);
                                        //System.out.println(bb.json());
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
```


* 4. 每6秒发送一次心跳程序，维持socket链接


```
for (;;){
                    Map map = new HashMap();
                    if(i >0) {
                        map.put("SubscribeEvent", true);
                        map.put("SubscribeRawBlock", false);
                    }else{
                        map.put("SubscribeJsonBlock", false);
                        map.put("SubscribeRawBlock", true);
                    }
                    //System.out.println(map);
                    ontSdk.getWebSocket().setReqId(i);
                    ontSdk.getWebSocket().sendSubscribe(map);     
                Thread.sleep(6000);
            }
```


* 5. 推送结果事例详解


以调用存证合约的put函数为例，

//存证合约abi.json文件部分内容如下

```
{
    "hash":"0x27f5ae9dd51499e7ac4fe6a5cc44526aff909669",
    "entrypoint":"Main",
    "functions":
    [

    ],
    "events":
    [
        {
            "name":"putRecord",
            "parameters":
            [
                {
                    "name":"arg1",
                    "type":"String"
                },
                {
                    "name":"arg2",
                    "type":"ByteArray"
                },
                {
                    "name":"arg3",
                    "type":"ByteArray"
                }
            ],
            "returntype":"Void"
        }
    ]
}
```
当调用put函数保存数据时，触发putRecord事件，websocket 推送的结果是{"putRecord", "arg1", "arg2", "arg3"}的十六进制字符串

例子如下：

```
RECV: {"Action":"Log","Desc":"SUCCESS","Error":0,"Result":{"Message":"Put","TxHash":"8cb32f3a1817d88d8562fdc0097a0f9aa75a926625c6644dfc5417273ca7ed71","ContractAddress":"80f6bff7645a84298a1a52aa3745f84dba6615cf"},"Version":"1.0.0"}
RECV: {"Action":"Notify","Desc":"SUCCESS","Error":0,"Result":[{"States":["7075745265636f7264","507574","6b6579","7b2244617461223a7b22416c6772697468656d223a22534d32222c2248617368223a22222c2254657874223a2276616c75652d7465737431222c225369676e6174757265223a22227d2c2243416b6579223a22222c225365714e6f223a22222c2254696d657374616d70223a307d"],"TxHash":"8cb32f3a1817d88d8562fdc0097a0f9aa75a926625c6644dfc5417273ca7ed71","ContractAddress":"80f6bff7645a84298a1a52aa3745f84dba6615cf"}],"Version":"1.0.0"}
```
## 5. 原生合约的使用说明

### 5.1 ont和ong资产转移

| 方法名 | 参数 | 返回值类型 | 描述 |
|:--|:---|:---|:--|
| sendTransfer       |String assetName, String sendAddr, String password, String recvAddr, long amount      | String|两个地址之间转移资产|
|sendTransferToMany  |String assetName, String sendAddr, String password, String[] recvAddr, long[] amount  |String |给多个地址转移资产|
|sendTransferFromMany|String assetName, String[] sendAddr, String[] password, String recvAddr, long[] amount|String |多个地址向某个地址转移资产|
|sendOngTransferFrom |String sendAddr, String password, String to, long amount                              |String |转移ong资产|



ont和ong合约address
```
private final String ontContract = "ff00000000000000000000000000000000000001";
private final String ongContract = "ff00000000000000000000000000000000000002";
```
State类字段如下：
```
public class State implements Serializable {
    public byte version;
    public Address from;
    public Address to;
    public BigInteger value;
    ...
  }
```
Transfers类字段如下：
```
public class Transfers implements Serializable {
    public byte version = 0;
    public State[] states;

    public Transfers(State[] states){
        this.states = states;
    }
    ...
  }
```
Contarct字段如下
```
public class Contract implements Serializable {
    public byte version;
    public byte[] code = new byte[0];
    public Address constracHash;
    public String method;
    public byte[] args;

    public Contract(byte version,byte[] code,Address constracHash, String method,byte[] args){
        this.version = version;
        if (code != null) {
            this.code = code;
        }
        this.constracHash = constracHash;
        this.method = method;
        this.args = args;
    }
    ....
  }
```
* 构造参数paramBytes
```
State state = new State(senderAddress, receiveAddress, new BigInteger(String.valueOf(amount)));
Transfers transfers = new Transfers(new State[]{state});
Contract contract = new Contract((byte) 0,null, Address.parse(contractAddr), "transfer", transfers.toArray());
byte[] paramBytes = contarct.toArray();
```
* 构造交易
```
public InvokeCode makeInvokeCodeTransaction(String codeAddr,String method,byte[] params, byte vmtype, Fee[] fees) throws SDKException {
        if(vmtype == VmType.NEOVM.value()) {
            Contract contract = new Contract((byte) 0, null, Address.parse(codeAddr), "", params);
            params = Helper.addBytes(new byte[]{0x67}, contract.toArray());
//            params = Helper.addBytes(params, new byte[]{0x69});
//            params = Helper.addBytes(params, Helper.hexToBytes(codeAddress));
        }else if(vmtype == VmType.WASMVM.value()) {
            Contract contract = new Contract((byte) 1, null, Address.parse(codeAddr), method, params);
            params = contract.toArray();
        }
        InvokeCode tx = new InvokeCode();
        tx.attributes = new Attribute[1];
        tx.attributes[0] = new Attribute();
        tx.attributes[0].usage = AttributeUsage.Nonce;
        tx.attributes[0].data = UUID.randomUUID().toString().getBytes();
        tx.code = params;
        tx.gasLimit = 0;
        tx.vmType = vmtype;
        tx.fee = fees;
        return tx;
    }
```
* 发送交易

请查看2.1节的发送交易

### 5.2 数字身份
数字身份相关介绍可参考[ONT ID 身份标识协议及信任框架](https://github.com/ontio/ontology-DID)。

|   方法名           |  参数                                                                     |   返回值类型  | 描述         |
|:--------          | :------                                                                  |:------------ |:-------     |
|sendRegister       |  Identity ident, String password                                         |    Identity  |向链上注册ontId|
|sendRegister       |   String  password                                                       |    Identity  |           |
|sendRegister       | String label,String password                                             |    Identity  |           |
|sendRegister       |String password, Map<String, Object> attrsMap                             |    Identity  |           |
|sendAddPubKey      |String ontid, String password, String newpubkey                           |    String    |给ontId添加公钥|
|sendAddPubKey      |String password, String ontid, String newpubkey, String recoveryScriptHash|    String    |           |
|sendRemovePubKey   |String ontid, String password, String removepk                            |    String    |删除公钥    |
|sendRemovePubKey   |String ontid, String password, byte[] key, String recoveryScriptHash      |    String    |           |
|sendAddRecovery    |String ontid, String password, String recoveryScriptHash                  |    String    |添加recovery |
|sendChangeRecovery |String ontid, String password, String newRecoveryScriptHash               |    String    |修改recovery  |
|sendUpdateAttribute|String ontid, String password, byte[] path, byte[] type, byte[] value     |    String    |更新属性     |
|sendGetDDO         |String ontid                                                              |    String    |获得DDo           |
|createOntIdClaim   |String signerOntid,String password, String context, Map<String, Object> claimMap, Map metaData|    String    | 创建ontId声明 |
|verifyOntIdClaim   |String claim                                                              |    String    |验证ontId声明           |
|getProof           |String txhash                                                             |    Object    | 获得merkle证明          |
|verifyMerkleProof  |String claim                                                              |    boolean   |验证merkle证明    |
|sendRemoveAttribute|String ontid, String password, byte[] path                                |    String    |删除属性       |
|sendGetPublicKeyId |String ontid,String password                                              |    String    |获得公钥Id         |
|sendGetPublicKeyStatus|String ontid,String password,byte[] pkId                               |    String    |获得公钥状态    |

### 5.3 数字存证
|   方法名           |  参数                                        |   返回值类型  | 描述         |
|:--------          | :------                                     |:------------ |:-------     |
|  sendPut  | String addr,String password,String key,String value | String       |  保存数据 |
| sendGet | String addr,String password,String key                | String       |  获得链上数据 |

## 附件

Neo字节码：
```
public enum ScriptOp {
    // Constants
    OP_0(0x00), // An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)
    OP_FALSE(OP_0),
    OP_PUSHBYTES1(0x01), // 0x01-0x4B The next opcode bytes is data to be pushed onto the stack
    OP_PUSHBYTES75(0x4B),
    OP_PUSHDATA1(0x4C), // The next byte contains the number of bytes to be pushed onto the stack.
    OP_PUSHDATA2(0x4D), // The next two bytes contain the number of bytes to be pushed onto the stack.
    OP_PUSHDATA4(0x4E), // The next four bytes contain the number of bytes to be pushed onto the stack.
    OP_1NEGATE(0x4F), // The number -1 is pushed onto the stack.
    //OP_RESERVED(0x50), // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    OP_1(0x51), // The number 1 is pushed onto the stack.
    OP_TRUE(OP_1),
    OP_2(0x52), // The number 2 is pushed onto the stack.
    OP_3(0x53), // The number 3 is pushed onto the stack.
    OP_4(0x54), // The number 4 is pushed onto the stack.
    OP_5(0x55), // The number 5 is pushed onto the stack.
    OP_6(0x56), // The number 6 is pushed onto the stack.
    OP_7(0x57), // The number 7 is pushed onto the stack.
    OP_8(0x58), // The number 8 is pushed onto the stack.
    OP_9(0x59), // The number 9 is pushed onto the stack.
    OP_10(0x5A), // The number 10 is pushed onto the stack.
    OP_11(0x5B), // The number 11 is pushed onto the stack.
    OP_12(0x5C), // The number 12 is pushed onto the stack.
    OP_13(0x5D), // The number 13 is pushed onto the stack.
    OP_14(0x5E), // The number 14 is pushed onto the stack.
    OP_15(0x5F), // The number 15 is pushed onto the stack.
    OP_16(0x60), // The number 16 is pushed onto the stack.


    // Flow control
    OP_NOP(0x61), // Does nothing.
    OP_JMP(0x62),
    OP_JMPIF(0x63),
    OP_JMPIFNOT(0x64),
    OP_CALL(0x65),
    OP_RET(0x66),
    OP_APPCALL(0x67),
    OP_SYSCALL(0x68),
    OP_VERIFY(0x69), // Marks transaction as invalid if top stack value is not true. True is removed, but false is not.
    OP_HALT(0x6A), // Marks transaction as invalid.


    // Stack
    OP_TOALTSTACK(0x6B), // Puts the input onto the top of the alt stack. Removes it from the main stack.
    OP_FROMALTSTACK(0x6C), // Puts the input onto the top of the main stack. Removes it from the alt stack.
    OP_2DROP(0x6D), // Removes the top two stack items.
    OP_2DUP(0x6E), // Duplicates the top two stack items.
    OP_3DUP(0x6F), // Duplicates the top three stack items.
    OP_2OVER(0x70), // Copies the pair of items two spaces back in the stack to the front.
    OP_2ROT(0x71), // The fifth and sixth items back are moved to the top of the stack.
    OP_2SWAP(0x72), // Swaps the top two pairs of items.
    OP_IFDUP(0x73), // If the top stack value is not 0, duplicate it.
    OP_DEPTH(0x74), // Puts the number of stack items onto the stack.
    OP_DROP(0x75), // Removes the top stack item.
    OP_DUP(0x76), // Duplicates the top stack item.
    OP_NIP(0x77), // Removes the second-to-top stack item.
    OP_OVER(0x78), // Copies the second-to-top stack item to the top.
    OP_PICK(0x79), // The item n back in the stack is copied to the top.
    OP_ROLL(0x7A), // The item n back in the stack is moved to the top.
    OP_ROT(0x7B), // The top three items on the stack are rotated to the left.
    OP_SWAP(0x7C), // The top two items on the stack are swapped.
    OP_TUCK(0x7D), // The item at the top of the stack is copied and inserted before the second-to-top item.


    // Splice
    OP_CAT(0x7E), // Concatenates two strings.
    OP_SUBSTR(0x7F), // Returns a section of a string.
    OP_LEFT(0x80), // Keeps only characters left of the specified point in a string.
    OP_RIGHT(0x81), // Keeps only characters right of the specified point in a string.
    OP_SIZE(0x82), // Returns the length of the input string.


    // Bitwise logic
    OP_INVERT(0x83), // Flips all of the bits in the input.
    OP_AND(0x84), // Boolean and between each bit in the inputs.
    OP_OR(0x85), // Boolean or between each bit in the inputs.
    OP_XOR(0x86), // Boolean exclusive or between each bit in the inputs.
    OP_EQUAL(0x87), // Returns 1 if the inputs are exactly equal, 0 otherwise.
    //OP_EQUALVERIFY(0x88), // Same as OP_EQUAL, but runs OP_VERIFY afterward.
    //OP_RESERVED1(0x89), // Transaction is invalid unless occuring in an unexecuted OP_IF branch
    //OP_RESERVED2(0x8A), // Transaction is invalid unless occuring in an unexecuted OP_IF branch

    // Arithmetic
    // Note: Arithmetic inputs are limited to signed 32-bit integers, but may overflow their output.
    OP_1ADD(0x8B), // 1 is added to the input.
    OP_1SUB(0x8C), // 1 is subtracted from the input.
    OP_2MUL(0x8D), // The input is multiplied by 2.
    OP_2DIV(0x8E), // The input is divided by 2.
    OP_NEGATE(0x8F), // The sign of the input is flipped.
    OP_ABS(0x90), // The input is made positive.
    OP_NOT(0x91), // If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    OP_0NOTEQUAL(0x92), // Returns 0 if the input is 0. 1 otherwise.
    OP_ADD(0x93), // a is added to b.
    OP_SUB(0x94), // b is subtracted from a.
    OP_MUL(0x95), // a is multiplied by b.
    OP_DIV(0x96), // a is divided by b.
    OP_MOD(0x97), // Returns the remainder after dividing a by b.
    OP_LSHIFT(0x98), // Shifts a left b bits, preserving sign.
    OP_RSHIFT(0x99), // Shifts a right b bits, preserving sign.
    OP_BOOLAND(0x9A), // If both a and b are not 0, the output is 1. Otherwise 0.
    OP_BOOLOR(0x9B), // If a or b is not 0, the output is 1. Otherwise 0.
    OP_NUMEQUAL(0x9C), // Returns 1 if the numbers are equal, 0 otherwise.
    //OP_NUMEQUALVERIFY(0x9D), // Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    OP_NUMNOTEQUAL(0x9E), // Returns 1 if the numbers are not equal, 0 otherwise.
    OP_LESSTHAN(0x9F), // Returns 1 if a is less than b, 0 otherwise.
    OP_GREATERTHAN(0xA0), // Returns 1 if a is greater than b, 0 otherwise.
    OP_LESSTHANOREQUAL(0xA1), // Returns 1 if a is less than or equal to b, 0 otherwise.
    OP_GREATERTHANOREQUAL(0xA2), // Returns 1 if a is greater than or equal to b, 0 otherwise.
    OP_MIN(0xA3), // Returns the smaller of a and b.
    OP_MAX(0xA4), // Returns the larger of a and b.
    OP_WITHIN(0xA5), // Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.


    // Crypto
    OP_RIPEMD160(0xA6), // The input is hashed using RIPEMD-160.
    OP_SHA1(0xA7), // The input is hashed using SHA-1.
    OP_SHA256(0xA8), // The input is hashed using SHA-256.
    OP_HASH160(0xA9), // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
    OP_HASH256(0xAA), // The input is hashed two times with SHA-256.
    //OP_CODESEPARATOR(0xAB), // All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.
    OP_CHECKSIG(0xAC), // The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
    //OP_CHECKSIGVERIFY(0xAD), // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
    OP_CHECKMULTISIG(0xAE), // For each signature and public key pair, OP_CHECKSIG is executed. If more public keys than signatures are listed, some key/sig pairs can fail. All signatures need to match a public key. If all signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one extra unused value is removed from the stack.
    //OP_CHECKMULTISIGVERIFY(0xAF), // Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.


    // Array
    OP_ARRAYSIZE(0xC0),
    OP_PACK(0xC1),
    OP_UNPACK(0xC2),
    OP_DISTINCT(0xC3),
    OP_SORT(0xC4),
    OP_REVERSE(0xC5),
    OP_CONCAT(0xC6),
    OP_UNION(0xC7),
    OP_INTERSECT(0xC8),
    OP_EXCEPT(0xC9),
    OP_TAKE(0xCA),
    OP_SKIP(0xCB),
    OP_PICKITEM(0xCC),
    OP_ALL(0xCD),
    OP_ANY(0xCE),
    OP_SUM(0xCF),
    OP_AVERAGE(0xD0),
    OP_MAXITEM(0xD1),
    OP_MINITEM(0xD2),
    ;
    private byte value;

    ScriptOp(int v) {
        value = (byte)v;
    }

    ScriptOp(ScriptOp v) {
        value = v.value;
    }

    public byte getByte() {
        return value;
    }

    public static ScriptOp valueOf(int v) {
        for (ScriptOp op : ScriptOp.values()) {
            if (op.value == (byte)v) {
                 return op;
            }
        }
        return null;
    }
}
```
