#include <iostream>
#include <WinSock2.h>
#include <windows.h>
#include"Functions.h"
#include "DES.h"

#include <time.h>

BigInteger* Sa = NULL; //DH协商的后的，DES对称密钥
DES DES_Container;     //DES对象
string warnings = "";
using namespace std;

#pragma comment(lib,"ws2_32.lib")
bool Initialization()
{
	//设置时间种子
	srand((unsigned int)time(NULL));

	//初始化动态链接库
	WSADATA WSAData;
	if (WSAStartup(2.2, &WSAData))
	{
		return FALSE;
	}
	return TRUE;
}


bool DH_KeyExchange(SOCKET S)
{
	//生成公钥和私钥
	BigInteger P(My_CrpytGenKey());
	BigInteger Self_Key(My_CrpytGenKey());

	//发送公钥给服务器端,接收服务器公钥
	string PublicKeyStr_B;
	if (S)
	{
		if (My_SendKey(S, P.toString().c_str()))
			PublicKeyStr_B = My_RecvKey(S);
	}
	else
		return FALSE;
	BigInteger Q(PublicKeyStr_B);

	//发送Ga，接收Gb,密钥计算
	string Gb_str;
	BigInteger* Ga = NULL;
	BigInteger* Gb = NULL;
	if (P > Q)
		Ga = new BigInteger(Q.modPow(Self_Key, P));
	else
		Ga = new BigInteger(P.modPow(Self_Key, Q));
	if (My_SendKey(S, Ga->toString().c_str()))
	{
		//接收Gb
		Gb_str = My_RecvKey(S);
		Gb = new BigInteger(Gb_str);
		if (P > Q)
			Sa = new BigInteger(Gb->modPow(Self_Key, P));
		else
			Sa = new BigInteger(Gb->modPow(Self_Key, Q));
	}
	return TRUE;
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
int main()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        //tell the user that we could nto find a usable
        //WinSock DLL;
        return -1;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
    {
        WSACleanup();
        return -1;
    }
    //The WinSock DLL is acceptable,Proceed  windows下版本的协商
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    SOCKET sockCli;//服务器套接字
    sockCli = socket(AF_INET, SOCK_STREAM, 0);//创建套接字  家族协议；流式套接字；默认值

    SOCKADDR_IN addrSer;//
    addrSer.sin_family = AF_INET;
    addrSer.sin_port = htons(5050);
    addrSer.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    int res = connect(sockCli, (SOCKADDR*)&addrSer, sizeof(SOCKADDR));//res为connect返回值 查阅相关函数，若为0则表示没有错误
    if (res != 0)
    {
        cout << "Client Connect Servrer Fail!" << endl;
        return -1;
    }
    else
    {
        cout << "Client Connect Servrer Success!" << endl;
    }

    char recv_hash[41];
    char calc_hash[41];//发空间和接收空间
	string message;
	string message_crypted;
    while (1)
    {
		recv(sockCli,recv_hash, 41, 0);
		char data[1024] = { 0 };
		recv(sockCli, data, 1024, 0);
		message_crypted = data;
		message = DES_Container.Decryption(message_crypted);
		My_HASH(message,calc_hash);
		if (!strcmp(recv_hash, calc_hash)) {
			cout << "From-Ser:>" << message << endl;
		}
		else {
			cout << "From-Ser:>" << "-----消息可能被篡改了----" << endl;
			cout << "From-Ser:>" << message << endl;
		}
       // recv(sockCli, recvbuf, 256, 0);
        //cout << "Ser:>" << recvbuf << endl;
        cout << "Cli:>";
		getline(cin,message);
		My_HASH(message, recv_hash);
		send(sockCli, recv_hash, 41, 0);
		message_crypted = DES_Container.Encryption(message);
        send(sockCli,message_crypted.c_str(), message_crypted.length(), 0);
    }
    closesocket(sockCli);
    WSACleanup();
    return 0;
}
bool My_SendKey(SOCKET S, const char Data[])
{
	if (send(S, Data, strlen(Data), 0) != SOCKET_ERROR)
		return TRUE;
	else
		return FALSE;
}


string My_RecvKey(SOCKET S)
{
	string KeyStr;
	char buffer[9] = { 0 };
	recv(S, buffer, 9, 0);
	if (strlen(buffer) == 8)
	{
		for (int index = 0; index < 8; index++)
		{
			KeyStr.push_back(buffer[index]);
		}
	}
	return KeyStr;
}


bool My_HASH(string Statement, char* hash)
{
	string Hash_256;
	HCRYPTPROV CSP;
	HCRYPTHASH HHash;

	char hash_data[41];
	DWORD hash_len = 41;

	if (!CryptAcquireContextA(&CSP, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
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