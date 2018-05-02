
## 合约调用权限管理

### 权限管理概述

权限管理合约可以记录智能合约的管理员信息，即记录`contract -> adminApp`（key-value）类型数据。通过权限管理合约实现用户和角色的管理，实现权限管理和用户合约的解耦。合约中的函数与角色对应，对应关系表明该角色可以调用相应的函数，角色与用户对应，每个用户可以拥有多个角色，用户拥有某个角色就意味着，该用户可以调用该角色授权的函数。

### 权限管理使用

#### 1. 如何在合约中调用权限管理合约
用户合约调用权限管理合约示例：
```

public class AppContract : SmartContract
{
	//导入权限管理合约
	[Appcall(codeAddress)]
	public static extern bool AuthorityManagerContract(string operation, object[] args);

	public static bool Main(string operation, object[] token, params object[] args)
	{
    //验证合约调用token的有效性
    if (!verifyToken(operation, token)) return false;

		if (operation == "foo1") {
			return foo1();
		}else if(operation == "foo2"){
      return foo2();
    }
	}
	public static bool foo1(){return true;}
  public static bool foo2(){return true;}
	public static bool verifyToken(string operation, object[] token)
	{
		byte[] publicKey = (byte[]) token[0]; //publicKey
		byte[] funcName = operation.AsByteArray(); //funcName
		byte[] tokenSig = (byte[]) token[1]; //tokenSig
		return AuthorityManagerContract("VerifyToken", publicKey, funcName, tokenSig);
	}
}
```
#### 2. 部署合约

#### 3. 验证合约调用token的有效性(用户合约调用权限管理合约)
```
VerifyToken(byte[] publicKey, byte[] funcName, byte[] tokenSig);
```
合约调用token包含三个部分：调用者的公钥，函数名，授权签名。


#### 下面步骤均为合约管理员调用权限管理合约进行操作。

#### 4. 登记合约管理员
```
SetContractAdmin(byte[] ontId)
```
合约通过调用ONT ID合约的SetContractAdmin方法，在ONT ID合约中绑定了合约管理者的身份，由其颁发的函数调用token，就可以被用于调用合约的函数。

#### 5. 绑定角色可调用的函数列表
```
bool AssignFuncsToRole(byte[] role, object[] funcNames);
```
必须由合约管理者调用，否则直接返回false；将所有函数自动绑定到role，若已经绑定，自动跳过，最后返回true。

#### 6. 绑定公钥到角色

```
bool AssignPksToRole(byte[] adminOntId, byte[] role, object[] Pks);
```
必须由合约管理者调用，否则直接返回false；Pks数组中的公钥被分配role角色，最后返回true。

#### 7. 转让合约管理权

```
void Transfer(byte[] newAdminOntId);
```
将管理权完全转让，newAdmin成为新管理员。

#### 8. 将合约调用权代理给其他人
```
//TODO
void Delegate(byte[] from, byte[] to, byte[] role, int period, int level);
void Withdraw(byte[] initiator, byte[] delegate, byte[] role);
```
角色拥有者可以将角色代理给其他人，from是转让者的公钥，to是代理人的公钥，role表示要代理的角色，period参数指定委托任期时间（以second为单位）。代理人可以再次将其角色代理给更多的人，level参数指定委托层次深度。例如，
level = 1: 此时代理人就无法将其角色再次代理出去；
角色拥有者可以提前将角色代理提前撤回，initiator是发起者，delegate是角色代理人，initiator将代理给delegate的角色提前撤回。
