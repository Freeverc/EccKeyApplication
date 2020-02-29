#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;

int main()
{
	cout << "\n                     Big Number Calculator                     \n" << endl;
	//point_conversion_form_t form = { POINT_CONVERSION_UNCOMPRESSED };

	const int KEY_X_LEN = 32;

	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BIGNUM* data1 = BN_new();
	BIGNUM* data2 = BN_new();
	BIGNUM* data3 = BN_new();
	BIGNUM* data4 = BN_new();
	char op;
	string s;

	BN_CTX_get(ctx);
	while (1)
	{
		cout << "Please input big number 1 (in hex): "<< endl;
		cin >> s;
		BN_hex2bn(&data1, s.c_str());
		cout << "Please input operator ( + - * / ):" << endl;
		cin >> op;
		cout << "Please input big number 2 (in hex): "<< endl;
		cin >> s;
		BN_hex2bn(&data2, s.c_str());
		switch (op)
		{
		case'+':
		BN_add(data3, data1, data2);
		cout << "The result is (in hex): "<< endl;
		cout << BN_bn2hex(data3) << endl;
		break;
		case'-':
		BN_sub(data3, data1, data2);
		cout << "The result is (in hex): "<< endl;
		cout << BN_bn2hex(data3) << endl;
		break;
		case'*':
		BN_mul(data3, data1, data2, ctx);
		cout << "The result is (in hex): "<< endl;
		cout << BN_bn2hex(data3) << endl;
		break;
		case'/':
		BN_div(data3, data4, data1, data2, ctx);
		cout << "The result is (in hex)(Quotient and remainder): "<< endl;
		cout << BN_bn2hex(data3) << endl;
		cout << BN_bn2hex(data4) << endl;
		break;
		default:
		cout << "The operator is wrong ! "<< endl;
		}
	}
	BN_free(data1);
	BN_free(data2);
	BN_free(data3);
	BN_CTX_end(ctx);
}