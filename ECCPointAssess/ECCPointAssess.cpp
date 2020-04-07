#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include <string>
#include <stdio.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace std;

int main()
{
    std::cout << "Hello World!\n";
	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BIGNUM* p = BN_new();
	BIGNUM* xBase = BN_new();
	BIGNUM* yBase = BN_new();
	BIGNUM* xStart = BN_new();
	BIGNUM* yStart = BN_new();
	BIGNUM* xCurrent = BN_new();
	BIGNUM* yCurrent = BN_new();
	BIGNUM* xEnd = BN_new();
	BIGNUM* yEnd = BN_new();
	BIGNUM* kStart = BN_new();
	BIGNUM* kCurrent = BN_new();
	BIGNUM* kEnd = BN_new();


	EC_GROUP* ecg = EC_GROUP_new_from_ecparameters();
	EC_POINT* ecpBase = EC_POINT_new(ecg);
	EC_POINT* ecpStart = EC_POINT_new(ecg);
	EC_POINT* ecpCurrent = EC_POINT_new(ecg);
	EC_POINT* ecpEnd = EC_POINT_new(ecg);
	clock_t tStart, tEnd;
	double totaltime;
	int sucess;
	string s;

	BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	BN_hex2bn(&xBase, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	BN_hex2bn(&yBase, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	cout << "The base point G : " << endl;
	cout << "X coordinate = " << BN_bn2hex(xBase) << endl;
	cout << "Y coordinate = " << BN_bn2hex(yBase) << endl;
	cout << "Uncompressed form : \n" << EC_POINT_point2hex(ecg, ecpBase, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

	// input
	cout << "please input X coordinate of G (in Hex):" << endl;
	cin >> s;
	BN_hex2bn(&xBase, s.c_str());
	EC_POINT_set_compressed_coordinates(ecg, ecpStart, xBase, 0, ctx);
	EC_POINT_set_compressed_coordinates(ecg, ecpEnd, xBase, 1, ctx);
	EC_POINT_get_affine_coordinates(ecg, ecpStart, xStart, yStart, ctx);
	EC_POINT_get_affine_coordinates(ecg, ecpEnd, xEnd, yEnd, ctx);
	cout << "y1 = " << BN_bn2hex(yStart) << endl;
	cout << "y2 = " << BN_bn2hex(yEnd) << endl;
	cout << "please input Y coordinate of G (in Hex):" << endl;
	cin >> s;
	BN_hex2bn(&yBase, s.c_str());
	EC_POINT_set_affine_coordinates(ecg, ecpBase, xBase, yBase, ctx);

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
