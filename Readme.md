#### This pargram was finished ,based on Diffie-Hellman protrol,DES and HASH.




### Functions:
   #####   1.Communication software based on C / S mode
   #####   2.Use DH key exchange protocol to negotiate key
   #####   3.Encrypting message with DES
   #####   4.Using hash digest to verify message authenticity


### How To Use：

         VS 2019+ ,make sure `X86 MODE`
  

the client.cpp and server.cpp were another main function to show this program.
You can repalce the DH_A.cpp and DH_B.cpp in the project.
Am I very cute? isn't? 



### [Warnings]

1.If You got an Unexpected interruption，Just Restart it！！！

2.IF You got an error：`eror:4996` Just add`#pragma warning(disable: 4996)` to you project.(Some compilers was Just warnning 4996)


------
#### 本程序基于DH密钥交换协议，DES加密协议和HASH杂凑摘要完成



### 实现功能：
   #####   1.基于C/S模式的通信软件
   #####   2.使用DH密钥交换协议商定密钥
   #####   3.使用对称加密算法DES进行加密
   #####   4.使用hash摘要，验证消息的真实性


### 使用：

         VS 2019或以上版本，选择x86模式，即可运行
  
根目录的两个CPP分别为CLIENT和SERVER的主函数，可以替换到项目中的DH_A.cpp(c)和DH_B.cpp(s)
就可以当成两份作业了，嘻嘻嘻，我是不是太贴心了~~~

### 【注意】

1.如果使用中出现，无法建立连接，或报错。
原因为C++内置库函数vector在出入栈时的问题
关闭重新运行即可！！！

2.如果报错4996，部分编译器下只是警告不影响运行，如果是error：加上下面这条代码
`#pragma warning(disable: 4996)`


