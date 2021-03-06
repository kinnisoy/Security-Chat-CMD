#include"Functions.h"
#include "DES.h"
#include <stdlib.h>
#include <time.h>

BigInteger* Sa = NULL; //DH协商的后的，DES对称密钥
DES DES_Container;     //DES对象
string warnings="\n===============================\n新建立的连接服务器不会主动发消息\n收到回复之后再发送，避免粘包\n==============END=================\n";


int main()
{	
	if (!Initialization())
		return FALSE;

	SOCKET S = My_Connect();
	if (S)
	{
		while (1)
		{
			if (DH_KeyExchange(S))
				if (Sa->toString().length() == 8)
					break;
		}
		cout << "==========================================" << endl;
		cout << "=====DDDD=================HH======HH======" << endl;
		cout << "=====DD==DD===============HH======HH======" << endl;
		cout << "=====DD==DDD==============HHHHHHHHHH======" << endl;
		cout << "=====DD==DD===============HH======HH======" << endl;
		cout << "=====DDDD=================HH======HH======" << endl;
		cout << "==========================================" << endl;

		//DES源密钥设定
		DES_Container.Set_The_Source_Key(Sa->toString());
		//DES子密钥生成
		DES_Container.Subkey_Generation();
	}
	string Statement;
	char hash_data[41],hash_new[41];
	cout << warnings << endl;
	cout << "消息正常显示，检测到不可信消息将会中断。（请文明聊天）" << endl;
	cout << "如果未显示DH字样，请重新连接......." << endl;
	while (1) {
		
		cout << "发送：";
		getline(cin, Statement);
		My_HASH(Statement, hash_data);
		send(S, hash_data,41, 0);
		string Encrypted_Data = DES_Container.Encryption(Statement);
		send(S, Encrypted_Data.c_str(), Encrypted_Data.length(), 0);
		while (1) {
			string Encrypted_Data;
			string Decrypted_Data;
			recv(S, hash_data, 41, 0);
			char data[1024] = { 0 };
			recv(S, data, 1024, 0);
			Encrypted_Data = data;
			Decrypted_Data = DES_Container.Decryption(Encrypted_Data);
			My_HASH(Decrypted_Data, hash_new);
			if (!strcmp(hash_data, hash_new)) {
				cout << "服务器消息：" << Decrypted_Data << endl;
				break;
			}
			else {
				cout << "（消息不可信，请重新建立连接）" << endl;
				exit(-1);
			}
		}

	}
	

	closesocket(S);
	return 0;
}


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


SOCKET My_Connect()
{
	//创建套接字
	SOCKET S = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	if (S == INVALID_SOCKET)
	{
		return FALSE;
	}

	//连接服务器
	sockaddr_in Server_Addr;
	ZeroMemory(&Server_Addr, sizeof(sockaddr_in));
	Server_Addr.sin_family = AF_INET;
	Server_Addr.sin_port = htons(8888);
	Server_Addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	if (WSAConnect(S, (sockaddr*)&Server_Addr, sizeof(sockaddr), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
	{
		closesocket(S);
		return FALSE;
	}
	return S;
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
