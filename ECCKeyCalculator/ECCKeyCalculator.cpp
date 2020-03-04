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
	cout << "\n                     ECC Point Calculator                     \n" << endl;
	//point_conversion_form_t form = { POINT_CONVERSION_UNCOMPRESSED };

	const int KEY_X_LEN = 32;

	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BIGNUM* x1 = BN_new();
	BIGNUM* y1 = BN_new();
	BIGNUM* x2 = BN_new();
	BIGNUM* y2 = BN_new();
	BIGNUM* x3 = BN_new();
	BIGNUM* y3 = BN_new();
	EC_GROUP* ecg = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_POINT* ecp1 = EC_POINT_new(ecg);
	EC_POINT* ecp2 = EC_POINT_new(ecg);
	EC_POINT* ecp3 = EC_POINT_new(ecg);
	char op;
	string s;

	BN_CTX_get(ctx);
	while (1)
	{
		cout << "Please input operator ( +  *  ):" << endl;
		cin >> op;
		switch (op)
		{
		case'+':
			cout << "Please input x cordinate of  Point 1 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&x1, s.c_str());
			cout << "Please input y cordinate of  Point 1 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&y1, s.c_str());
			EC_POINT_set_affine_coordinates(ecg, ecp1, x1, y1, ctx);
			
			cout << "Please input x cordinate of  Point 2 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&x2, s.c_str());
			cout << "Please input y cordinate of  Point 2 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&y2, s.c_str());
			EC_POINT_set_affine_coordinates(ecg, ecp2, x2, y2, ctx);
			EC_POINT_add(ecg, ecp3, ecp1, ecp2, ctx);
			break;
		case'*':
			cout << "Please input big number k (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&x2, s.c_str());
			
			cout << "Please input x cordinate of  Point 1 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&x1, s.c_str());
			cout << "Please input y cordinate of  Point 1 (in hex): " << endl;
			cin >> s;
			BN_hex2bn(&y1, s.c_str());
			EC_POINT_set_affine_coordinates(ecg, ecp1, x1, y1, ctx);
			EC_POINT_mul(ecg, ecp3, NULL, ecp1, x2, ctx);
			break;
		default:
			cout << "The operator is wrong ! " << endl;
		}
		EC_POINT_get_affine_coordinates(ecg, ecp3, x3, y3, ctx);
		cout << "The result is (in hex): " << endl;
		cout << "x = " << BN_bn2hex(x3) << endl;
		cout << "y = " << BN_bn2hex(y3) << endl;
	}

	BN_free(x1);
	BN_free(y1);
	BN_free(x2);
	BN_free(y2);
	BN_free(x3);
	BN_free(y3);
	EC_GROUP_free(ecg);
	EC_POINT_free(ecp1);
	EC_POINT_free(ecp2);
	EC_POINT_free(ecp3);
	BN_CTX_end(ctx);
}