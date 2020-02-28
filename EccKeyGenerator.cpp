#include <iostream>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;
int main()
{
	point_conversion_form_t form = { POINT_CONVERSION_UNCOMPRESSED };
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);
    std::cout << "Hello World!\n";
	BIGNUM* p = BN_new();
	BIGNUM* Gx = BN_new();
	BIGNUM* Gy = BN_new();
	BIGNUM* kStart = BN_new();
	BIGNUM* kCurrent = BN_new();
	BIGNUM* kEnd = BN_new();
	int sucess;
	string s;
	BN_hex2bn(&p,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	BN_hex2bn(&Gx, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	BN_hex2bn(&Gy, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	cout << "x cordinate value of G :" << BN_bn2hex(Gx) << endl;
	cout << "y cordinate value of G :" << BN_bn2hex(Gy) << endl;
	
	// input
	cout << "please input start value of k (int Hex):" << endl;
    cin >> s;
	BN_hex2bn(&kStart, s.c_str());
    cout << "please input end   value of k (int Hex):" << endl;
    cin >> s;
	BN_hex2bn(&kEnd, s.c_str());
	if (BN_cmp(kStart, kEnd) == 1)
		BN_swap(kStart, kEnd);
	kCurrent = BN_dup(kStart);
	cout << "start   value of k :" << BN_bn2hex(kStart) << endl;
	cout << "current value of k :" << BN_bn2hex(kCurrent) << endl;
	cout << "end     value of k :" << BN_bn2hex(kEnd) << endl;

	BIGNUM* increment = BN_new();
	BN_one(increment);
	std::cout << "increment = " << BN_bn2hex(increment) << endl;
	EC_KEY* keyCurrent = EC_KEY_new();
	EC_GROUP* ecg = EC_GROUP_new_by_curve_name(NID_secp256k1);

	// gen keys 
	EC_POINT *ecpStart = EC_POINT_new(ecg); 
	EC_POINT *ecpCurrent = EC_POINT_new(ecg); 
	BN_CTX_get(ctx);
	EC_POINT_set_compressed_coordinates(ecg, ecpStart, Gx, 0, ctx);
	s = EC_POINT_point2hex(ecg, ecpStart, form, ctx);
	cout << s << endl;
	//EC_POINT_new_by_curve_name(NID_secp256k1);

	//BN_CTX;
	//EC_POINT_bn2point(ecg, Gx, ecpStart);
	//EC_POINT *ecpCurrent = EC_POINT_new(); 
	BN_CTX_get(ctx);
	EC_POINT_mul(ecg, ecpCurrent, NULL, ecpStart, kCurrent, ctx);
	s = EC_POINT_point2hex(ecg, ecpCurrent, form, ctx);
	cout << "private key = " << BN_bn2hex(kCurrent) << endl;
	cout << "public  key = "<< s << endl;
	while(BN_cmp(kCurrent, kEnd) < 1)
	{
		EC_POINT_add(ecg, ecpCurrent, ecpCurrent, ecpCurrent, ctx);
		s = EC_POINT_point2hex(ecg, ecpCurrent, form, ctx);
		cout << "private key = " << BN_bn2hex(kCurrent) << endl;
		cout << "public  key = "<< s << endl;
		BN_add(kCurrent, kCurrent, increment);
	}




	BN_CTX_end(ctx);
	BN_free(kStart);
	BN_free(kCurrent);
	BN_free(kEnd);
	EC_GROUP_free(ecg);
}
