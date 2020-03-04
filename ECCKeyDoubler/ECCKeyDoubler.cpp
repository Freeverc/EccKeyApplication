#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <stdio.h>
#include <time.h>
#include <conio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;

int main()
{
	cout << "\n                   Database Searching By Doubling!                  \n" << endl;
	//point_conversion_form_t form = { POINT_CONVERSION_UNCOMPRESSED };

	const int KEY_X_LEN = 32;

	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BIGNUM* p = BN_new();
	BIGNUM* xBase = BN_new();
	BIGNUM* yBase = BN_new();
	BIGNUM* xStart = BN_new();
	//BIGNUM* yStart = BN_new();
	BIGNUM* xCurrent = BN_new();
	BIGNUM* yCurrent = BN_new();
	//BIGNUM* xEnd = BN_new();
	//BIGNUM* yEnd = BN_new();
	BIGNUM* xBuffer = BN_new();
	BIGNUM* kStart = BN_new();
	BIGNUM* kCurrent = BN_new();
	//BIGNUM* kEnd = BN_new();
	BIGNUM* n = BN_new();
	BIGNUM* increment = BN_new();
	EC_GROUP* ecg = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_POINT* ecpBase = EC_POINT_new(ecg);
	EC_POINT* ecpStart = EC_POINT_new(ecg);
	EC_POINT* ecpCurrent = EC_POINT_new(ecg);
	EC_POINT* ecpEnd = EC_POINT_new(ecg);
	clock_t tStart, tEnd;
	string s;

	BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	BN_hex2bn(&xBase, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	BN_hex2bn(&yBase, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	cout << "The default base point G : " << endl;
	cout << "X coordinate = " << BN_bn2hex(xBase) << endl;
	cout << "Y coordinate = " << BN_bn2hex(yBase) << endl;
	cout << "Uncompressed form : \n" << EC_POINT_point2hex(ecg, ecpBase, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

	// input
	cout << "please input X coordinate of G (in Hex):" << endl;
	cin >> s;
	BN_hex2bn(&xBase, s.c_str());
	EC_POINT_set_compressed_coordinates(ecg, ecpBase, xBase, 0, ctx);
	BN_zero(n);
	BN_hex2bn(&kStart, "2");


	// searching by doubling G
	tStart = clock();
	BN_CTX_get(ctx);
	xCurrent = BN_dup(xBase);
	yCurrent = BN_dup(yBase);
	kCurrent = BN_dup(kStart);
	EC_POINT_copy(ecpCurrent, ecpBase);
	unsigned char bufKeyX[KEY_X_LEN + 10];
	FILE* dataFile = fopen("database\\publicKeys.kdb", "rb");
	FILE* searchFile = fopen("database\\doubleSearchKeys.kdb", "wb");
	FILE* searchFileVisual = fopen("database\\doubleSearchKeys.txt", "w");

	BN_one(increment);
	long offset = 0;
	int foundNum = 0;
	int key;
	int pauseFlag = 0;
	double totaltime;
	int found = 0;
	cout << " Searching...... Please wait!\n Press space to pause or continue!" << endl;
	while (found == 0)
	{
		if (_kbhit())
		{
			key = _getch();
			if (key == 32)
			{
				pauseFlag = 1 - pauseFlag;
				if (pauseFlag)
				{
					tEnd = clock();
					totaltime = (double)(tEnd - tStart) / CLOCKS_PER_SEC;
					BN_exp(kCurrent, kStart, n, ctx);
					cout << "Time used : " << totaltime << " seconds." << endl;
					cout << "n = " << BN_bn2hex(n) << endl;
					cout << "the private key = " << BN_bn2hex(kCurrent) << endl;
					cout << " Searching Paused! Press space to continue!" << endl;
				}
				else
					cout << " Continue searching! Press space to pause!" << endl;
			}
		}
		if (pauseFlag == 0)
		{
			//cout << "searching flag" << endl;
			fseek(dataFile, offset, SEEK_SET);
			found = 0;
			while (!feof(dataFile))
			{
				fread(bufKeyX, sizeof(unsigned char), KEY_X_LEN, dataFile);
				BN_bin2bn(bufKeyX, KEY_X_LEN, xBuffer);
				//cout<< "buffer :  " << BN_bn2hex(xBuffer) << endl;
				if (BN_cmp(xBuffer, xCurrent) == 0)
				{
					foundNum++;
					found = 1;
					offset = ftell(dataFile);
					fwrite(bufKeyX, sizeof(unsigned char), KEY_X_LEN, searchFile);
					s = BN_bn2hex(xCurrent);
					fputs(s.c_str(), searchFileVisual);
					BN_exp(kCurrent, kStart, n, ctx);
					BN_add(n, n, increment);
					cout << "found " << endl;
					cout << "n = " << BN_bn2hex(n) << endl;
					cout << "the private key = " << BN_bn2hex(kCurrent) << endl;
					cout << "x of public key = " << BN_bn2hex(xCurrent) << endl;
					cout << "y of public key = " << BN_bn2hex(yCurrent) << endl;
					break;
				}
			}
			if (found)
			{
				cout << "found" << endl;
				break;
			}
			BN_CTX_get(ctx);
			EC_POINT_dbl(ecg, ecpCurrent, ecpCurrent, ctx);
			EC_POINT_get_affine_coordinates(ecg, ecpCurrent, xCurrent, yCurrent, ctx);
			BN_add(n, n, increment);
			//EC_POINT_mul(ecg, ecpCurrent, NULL, ecpStart, kCurrent, ctx);
			//fwrite("\n", sizeof(unsigned char), 1, dataFile);
			//fputs(s.c_str(), dataFile);
			//cout << "the private key = " << BN_bn2hex(kCurrent) << endl;
			//cout << "x of public key = " << BN_bn2hex(xCurrent) << endl;
			//cout << "y of public key = " << BN_bn2hex(yCurrent) << endl;
			//cout << "Uncompressed form : \n" << EC_POINT_point2hex(ecg, ecpCurrent, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
		}
	}


	BN_CTX_end(ctx);
	BN_free(xBase);
	BN_free(yBase);
	BN_free(xStart);
	//BN_free(yStart);
	BN_free(xCurrent);
	BN_free(yCurrent);
	//BN_free(xEnd);
	//BN_free(yEnd);
	BN_free(kStart);
	BN_free(kCurrent);
	//BN_free(kEnd);
	BN_free(n);
	BN_free(increment);
	EC_GROUP_free(ecg);
	EC_POINT_free(ecpBase);
	EC_POINT_free(ecpStart);
	EC_POINT_free(ecpCurrent);
	//EC_POINT_free(ecpEnd);
	fclose(dataFile);
	fclose(searchFile);
	fclose(searchFileVisual);
	tEnd = clock();
	totaltime = (double)(tEnd - tStart) / CLOCKS_PER_SEC;
	cout << "Database searching used : " << totaltime << " seconds." << endl;
	cout << "totaly found : " << foundNum << endl;
	system("PAUSE");
}
