#include <iostream>
#include <WinSock2.h>
#include <windows.h>
#include "wincrypt.h"//这个库是hash函数用到的
#include "Functions.h"
#include "DES.h"
#include <time.h>
#include "string.h"



using namespace std;

#pragma comment(lib,"ws2_32.lib") //引用静态链接库
BigInteger* Sb = NULL; //DH协商的后的，DES对称密钥
DES DES_Container;     //DES对象


int main()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        return -1;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
    {
        WSACleanup();
        return -1;
    }
    SOCKET sockSer;//服务器套接字
    sockSer = socket(AF_INET, SOCK_STREAM, 0);//创建套接字，AF_INET代表IP家族,0是默认的方式创建  有连接是流式 无连接是数据包套接字

    SOCKADDR_IN addrSer, addrCli;
    addrSer.sin_family = AF_INET;
    addrSer.sin_port = htons(5050);
    addrSer.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    bind(sockSer, (SOCKADDR*)&addrSer, sizeof(SOCKADDR));//绑定套接字 跟服务器的相关地址信息进行绑定

    listen(sockSer, 5);//监听套接字 5是队列大小

    SOCKET sockConn;//给出一个相应的套接字
    int len = sizeof(SOCKADDR);

    cout << "Server Wait Client Connect......." << endl;
    sockConn = accept(sockSer, (SOCKADDR*)&addrCli, &len);//处理新到连接 3个参数分别是服务器的套接字号；客户端地址，相应地址层度的地址以地址形式传递


    if (sockConn == INVALID_SOCKET)//INVALID_SOCKET非法套接字
    {
        cout << "Server Accept Client Connect Fail" << endl;
        return -1;
    }
    else
    {
        cout << "Server Accept Client Connect Success" << endl;
        // return ;
    }
    //设置时间种子
    srand((unsigned int)time(NULL));
    string Statement, Encrypted_Data;//获取键盘输入的明文字符串
    char hash_data[41], hash_new[41]; //保存hash的两个数组
   while (1) {
       
        
           cout << "Ser：>";
           getline(cin,Statement);
           My_HASH(Statement, hash_data);
            /*先发hash*/
           send(sockConn, hash_data, 41, 0);
            /*对明文加密，这里针对的是字符串，所以你那边也用字符串比较好*/
            Encrypted_Data = DES_Container.Encryption(Statement);
            /*发送的时候，只能发char    所以用了.c_str()转换成char了*/
            send(sockConn, Encrypted_Data.c_str(), Encrypted_Data.length(), 0);
         
        
            /*后面的接收就也是先接收hash，这样了*/
            recv(sockConn, hash_data, 41, 0);//接收.
            char data[1024] = { 0 };
            recv(sockConn, data, 1024, 0);
            Encrypted_Data = data;
            Statement = DES_Container.Decryption(Encrypted_Data);
            My_HASH(Statement, hash_new);
            if (!strcmp(hash_data, hash_new)) {
                cout << "From-Cli:>" <<Statement << endl;
            }
            else {
                cout << "From-Cli:>" << "-----消息可能被篡改了----" << endl;
                cout << "From-Cli:>" << Statement << endl;
            }
            
        }

        closesocket(sockSer);//
        WSACleanup();//清除版本信息
        return 0;
    

}
bool DH_KeyExchange(SOCKET S_New)
{
    //生成公钥和私钥
    BigInteger Q(My_CrpytGenKey());
    BigInteger Self_Key(My_CrpytGenKey());

    string PublicKeyStr_A;
    if (S_New)
    {
        PublicKeyStr_A = My_RecvKey(S_New);
        if (PublicKeyStr_A.length() > 0)
        {
            My_SendKey(S_New, Q.toString().c_str());
        }
    }
    else
        return FALSE;
    BigInteger P(PublicKeyStr_A);

    //接收Ga,发送Gb,密钥计算
    string Ga_str;
    BigInteger* Ga = NULL;
    BigInteger* Gb = NULL;
    if (P > Q)
        Gb = new BigInteger(Q.modPow(Self_Key, P));
    else
        Gb = new BigInteger(P.modPow(Self_Key, Q));
    if ((Ga_str = My_RecvKey(S_New)).length() > 0)
    {
        Ga = new BigInteger(Ga_str);
        My_SendKey(S_New, Gb->toString().c_str());

        //最终通信密钥计算
        if (P > Q)
            Sb = new BigInteger(Ga->modPow(Self_Key, P));
        else
            Sb = new BigInteger(Ga->modPow(Self_Key, Q));
    }
    return TRUE;
}
bool My_SendKey(SOCKET sockConn, const char Data[])
{
    if (send(sockConn, Data, strlen(Data), 0) != SOCKET_ERROR)
        return TRUE;
    else
        return FALSE;
}


string My_RecvKey(SOCKET sockConn)
{
    string KeyStr;
    char buffer[9] = { 0 };
    recv(sockConn, buffer, 9, 0);
    if (strlen(buffer) == 8)
    {
        for (int index = 0; index < 8; index++)
        {
            KeyStr.push_back(buffer[index]);
        }
    }
    return KeyStr;
}


BigInteger My_CrpytGenKey()
{
    while (1)
    {
        int Num_OF_Access = 0;

        //费马素性检验
        string Hex_Number_P = My_RandKeyStr();
        BigInteger P(Hex_Number_P);
        for (int i = 0; i < 20; i++)
        {
            string Hex_Number_A = My_RandKeyStr();
            BigInteger A(Hex_Number_A);
            if ((A >= A.TWO) && (A <= P - P.TWO))
            {
                BigInteger Container(A.modInverse(P));
                if (Container != Container.ZERO)
                {
                    BigInteger Test(A.modPow(P - P.ONE, P));
                    if (Test == Test.ONE)
                        Num_OF_Access++;
                    else
                        break;
                }
                else
                    break;
            }
            else
                i--;
        }
        if (Num_OF_Access == 20)
            return P;
    }
}


string My_RandKeyStr()
{
    //随机生成16进制字符串用于生成大数P
    string Hex_Str;
    string Hex_Number = "0123456789ABCDEF";

    for (int i = 0; i < 8; i++)
    {
        unsigned int index = rand() % 16;
        Hex_Str.push_back(Hex_Number[index]);
    }
    return Hex_Str;
}


bool My_HASH(string Statement, char* hash)
{
    string Hash_256;
    HCRYPTPROV CSP;
    HCRYPTHASH HHash;

    char hash_data[41];
    DWORD hash_len = 41;

    if (!CryptAcquireContextA(&CSP, NULL,NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
    else if (!CryptCreateHash(CSP, CALG_SHA1, 0, 0, &HHash))
        return FALSE;
    else if (!CryptHashData(HHash, (const BYTE*)Statement.c_str(), Statement.length(), 0))
        return FALSE;
    else if (!CryptGetHashParam(HHash, HP_HASHVAL, (BYTE*)hash_data, &hash_len, 0))
        return FALSE;

    for (int i = 0; i <= hash_len - 1; i++)
    {
        int hash_bit = hash_data[i];
        int first = (hash_bit & 0xf0) >> 4;
        int second = hash_bit & 0x0f;
        char tmp[2];
        itoa(first, tmp, 16);
        hash[i * 2] = tmp[0];
        itoa(second, tmp, 16);
        hash[i * 2 + 1] = tmp[0];
    }
    hash[40] = '\0';

    return TRUE;
}