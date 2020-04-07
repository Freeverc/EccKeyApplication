#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;

void BN_sqrt(BIGNUM* r, BIGNUM* n)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
    BIGNUM* le = BN_new();
    BIGNUM* mi = BN_new();
    BIGNUM* ri = BN_new();
    BIGNUM* temp = BN_new();
	BN_one(temp);
	if (BN_cmp(temp, n) == 0)
	{
		BN_one(r);
		return;
	}
	BN_zero(le);
	BN_copy(ri, n);
	BN_add(temp, le, ri);
	BN_rshift1(mi, temp);
	int find = 0;
	while (BN_cmp(le, mi) < 0)
	{
		BN_sqr(temp, mi, ctx);
		//cout << "le = " << BN_bn2dec(le) << endl;
		//cout << "mi = " << BN_bn2dec(mi) << endl;
		//cout << "ri = " << BN_bn2dec(ri) << endl;
		//cout << "sqr = " << BN_bn2dec(temp) << endl;
		int cmp = BN_cmp(temp, n);
		if (cmp == 0)
		{
			find = 1;
			break;
		}
		else if (cmp == -1)
			BN_copy(le, mi);
		else if (cmp == 1)
			BN_copy(ri, mi);
		BN_add(temp, le, ri);
		BN_rshift1(mi, temp);
	}
	if (find)
		BN_copy(r, mi);
	else
		BN_zero(ri);
	BN_free(le);
	BN_free(mi);
	BN_free(ri);
	BN_free(temp);
	BN_CTX_end(ctx);
	return;
}

void BN_mod_sqrt(BIGNUM* r, BIGNUM* n, BIGNUM* N)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM* zeroNum = BN_new();
	BIGNUM* N2 = BN_new();
	BN_zero(zeroNum);
	BN_sqr(N2, N, ctx);
	while (BN_cmp(n, N2) <= 0) {
		//cout << "n = " << BN_bn2hex(n) << endl;
		//cout << "r = " << BN_bn2hex(r) << endl;
		BN_sqrt(r, n);
		if (BN_cmp(r, zeroNum) > 0)
			break;
		BN_add(n, n, N);
	}
	BN_free(zeroNum);
	BN_CTX_end(ctx);
	return;
}

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
		BN_zero(data3);
		cout << "Please input big number 1 (in hex): "<< endl;
		cin >> s;
		BN_hex2bn(&data1, s.c_str());
		cout << "Please input operator ( + - * / r R):" << endl;
		cout << "r: number 3 = square root of number 1" << endl;
		cout << "R: number 3 = square root of number 1 mod number2" << endl;
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
		case 'r':
		BN_sqrt(data3, data1);
		cout << "The suare root of data1 is (in hex): "<< endl;
		cout << BN_bn2hex(data3) << endl;
		break;
		case 'R':
		BN_mod_sqrt(data3, data1, data2);
		cout << "The mod-data2  suare root of data1 is (in hex): "<< endl;
		cout << BN_bn2hex(data3) << endl;
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