#include <iostream>
#include <WinSock2.h>
#include <windows.h>
#include "wincrypt.h"//�������hash�����õ���
#include "Functions.h"
#include "DES.h"
#include <time.h>
#include "string.h"



using namespace std;

#pragma comment(lib,"ws2_32.lib") //���þ�̬���ӿ�
BigInteger* Sb = NULL; //DHЭ�̵ĺ�ģ�DES�Գ���Կ
DES DES_Container;     //DES����


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
    SOCKET sockSer;//�������׽���
    sockSer = socket(AF_INET, SOCK_STREAM, 0);//�����׽��֣�AF_INET����IP����,0��Ĭ�ϵķ�ʽ����  ����������ʽ �����������ݰ��׽���

    SOCKADDR_IN addrSer, addrCli;
    addrSer.sin_family = AF_INET;
    addrSer.sin_port = htons(5050);
    addrSer.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    bind(sockSer, (SOCKADDR*)&addrSer, sizeof(SOCKADDR));//���׽��� ������������ص�ַ��Ϣ���а�

    listen(sockSer, 5);//�����׽��� 5�Ƕ��д�С

    SOCKET sockConn;//����һ����Ӧ���׽���
    int len = sizeof(SOCKADDR);

    cout << "Server Wait Client Connect......." << endl;
    sockConn = accept(sockSer, (SOCKADDR*)&addrCli, &len);//�����µ����� 3�������ֱ��Ƿ��������׽��ֺţ��ͻ��˵�ַ����Ӧ��ַ��ȵĵ�ַ�Ե�ַ��ʽ����


    if (sockConn == INVALID_SOCKET)//INVALID_SOCKET�Ƿ��׽���
    {
        cout << "Server Accept Client Connect Fail" << endl;
        return -1;
    }
    else
    {
        cout << "Server Accept Client Connect Success" << endl;
        // return ;
    }
    //����ʱ������
    srand((unsigned int)time(NULL));
    string Statement, Encrypted_Data;//��ȡ��������������ַ���
    char hash_data[41], hash_new[41]; //����hash����������
   while (1) {
       
        
           cout << "Ser��>";
           getline(cin,Statement);
           My_HASH(Statement, hash_data);
            /*�ȷ�hash*/
           send(sockConn, hash_data, 41, 0);
            /*�����ļ��ܣ�������Ե����ַ������������Ǳ�Ҳ���ַ����ȽϺ�*/
            Encrypted_Data = DES_Container.Encryption(Statement);
            /*���͵�ʱ��ֻ�ܷ�char    ��������.c_str()ת����char��*/
            send(sockConn, Encrypted_Data.c_str(), Encrypted_Data.length(), 0);
         
        
            /*����Ľ��վ�Ҳ���Ƚ���hash��������*/
            recv(sockConn, hash_data, 41, 0);//����.
            char data[1024] = { 0 };
            recv(sockConn, data, 1024, 0);
            Encrypted_Data = data;
            Statement = DES_Container.Decryption(Encrypted_Data);
            My_HASH(Statement, hash_new);
            if (!strcmp(hash_data, hash_new)) {
                cout << "From-Cli:>" <<Statement << endl;
            }
            else {
                cout << "From-Cli:>" << "-----��Ϣ���ܱ��۸���----" << endl;
                cout << "From-Cli:>" << Statement << endl;
            }
            
        }

        closesocket(sockSer);//
        WSACleanup();//����汾��Ϣ
        return 0;
    

}
bool DH_KeyExchange(SOCKET S_New)
{
    //���ɹ�Կ��˽Կ
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

    //����Ga,����Gb,��Կ����
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

        //����ͨ����Կ����
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

        //�������Լ���
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
    //�������16�����ַ����������ɴ���P
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