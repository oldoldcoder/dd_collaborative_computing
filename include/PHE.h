/**
* @author: WTY
* @date: 2024/7/4
* @description: Definition of constants, operations, and header files
*/


#ifndef PHE_H
#define PHE_H

#include <bits/stdc++.h>
#include <openssl/bn.h>
using namespace std;

// 设计一个公钥类
class PublicKey {
public:
    // 构造函数
    PublicKey(int k_M, int k_r, int k_L, int k_p, int k_q, BIGNUM* N, BIGNUM* zero1_prime, BIGNUM* zero2_prime) {
        this->k_M = k_M;
        this->k_r = k_r;
        this->k_L = k_L;
        this->k_p = k_p;
        this->k_q = k_q;
        this->N = BN_dup(N);
        this->zero1_prime = BN_dup(zero1_prime);
        this->zero2_prime = BN_dup(zero2_prime);
    }

    int get_k_M() {
        return k_M;
    }

    int get_k_r() {
        return k_r;
    }

    int get_k_L() {
        return k_L;
    }

    int get_k_p() {
        return k_p;
    }

    int get_k_q() {
        return k_q;
    }

    BIGNUM* get_N() {
        return BN_dup(N);
    }

    BIGNUM* get_zero1_prime() {
        return BN_dup(zero1_prime);
    }

    BIGNUM* get_zero2_prime() {
        return BN_dup(zero2_prime);
    }

    ~PublicKey() {
        BN_free(N);
        BN_free(zero1_prime);
        BN_free(zero2_prime);
    }

private:
    int k_M;
    int k_r;
    int k_L;
    int k_p;
    int k_q;
    BIGNUM* N;
    BIGNUM* zero1_prime;
    BIGNUM* zero2_prime;
};

// 定义数据拥有者
class DO {
public:
    // 构造函数
    DO(BIGNUM* x, PublicKey* pk, PrivateKey* sk) {
        this->x = BN_dup(x);
        this->pk = pk;
        this->sk = sk;
    }

    BIGNUM* get_x() {
        return BN_dup(x);
    }

    PublicKey* get_pk() {
        return new PublicKey(*pk);
    }

    PrivateKey* get_sk() {
        return new PrivateKey(*sk);
    }

    void set_x(BIGNUM* x) {
        this->x = BN_dup(x);
    }

    void set_pk(PublicKey* pk) {
        this->pk = pk;
    }

    void set_sk(PrivateKey* sk) {
        this->sk = sk;
    }

    ~DO() {
        BN_free(x);
        delete pk;
        delete sk;
    }

private:
    // 持有的数据
    BIGNUM* x;

    // 持有公钥
    PublicKey* pk;

    // 持有私钥
    PrivateKey* sk;
};

// 声明公钥指针
extern PublicKey* pk;

// 定义分箱的结构体
struct Bin {
    // 定义分箱范围
    BIGNUM* lower;
    BIGNUM* upper;
    // 定义分箱存储的元素
    vector<BIGNUM*> elements;
};

/**
 * @Method: 计算算数平方根，结果向上取整
 * @param BIGNUM*  n 待开方的数
 * @return BIGNUM*  sqrt(n)
 */
BIGNUM* BN_sqrt(const BIGNUM* n);

/**
 * @Method 生成PHE公钥
 * @return void
 */
void generatePublicKeys_PHE();

/**
 * @Method 生成公钥和私钥
 * @return void
 */
void InitKeys_PHE(int a, int b, int c, int d, int e);

/**
 * @Method 加密
 * @param BIGNUM*  m 消息
 * @param PrivateKey *sk 公钥
 * @return BIGNUM* [[m]] 密文消息
 */
BIGNUM* encrypt_PHE(BIGNUM* m, PublicKey* pk);

/**
 * @Method 解密
 * @param BIGNUM* E_m 密文消息
 * @param PrivateKey *sk 私钥
 * @return BIGNUM* m 消息
 */
BIGNUM* decrypt_PHE(BIGNUM* E_m, PrivateKey* sk);

/**
 *@Method 均值计算
 *@param vector<BIGNUM*> data_list 数据集合
 *@return BIGNUM* avg 均值
 */
BIGNUM* avg_PHE(vector<BIGNUM*> data_list);

/**
 *@Method 数据比较
 *@param BIGNUM* x1 第一个数据
 *@param BIGNUM* x2 第二个数据
 *@return bool true:x1 > x2;false:x1 <= x2
 */
bool compare_PHE(BIGNUM* x1, BIGNUM* x2);

/**
 *@Method 相等性测试
 *@param BIGNUM* x1 第一个数据
 *@param BIGNUM* x2 第二个数据
 *@return bool true:x1 == x2;false:x1 != x2
 */
bool equal_PHE(BIGNUM* x1, BIGNUM* x2);

/**
 *@Method 求最小值
 *@param vector<BIGNUM*> datas N个数据拥有者持有的数据集
 *@param int left 数据集的左边界
 *@param int right 数据集的右边界
 *@return BIGNUM* min 最小值
 */
BIGNUM* min_PHE(vector<BIGNUM*> datas, int left, int right);

/**
 *@Method 求最大值
 *@param vector<BIGNUM*> datas N个数据拥有者持有的数据集
 *@param int left 数据集的左边界
 *@param int right 数据集的右边界
 *@return BIGNUM* max 最大值
 */
BIGNUM* max_PHE(vector<BIGNUM*> datas, int left, int right);

/*
 *@Method 包含关系测试
 *@param BIGNUM* x 用户DO1持有的数据
 *@param BIGNUM* y1 用户DO2持有的数据
 *@param BIGNUM* y2 用户DO2持有的数据
 *@return bool true:x not in [y1,y2];false:x in [y1,y2]
 */
bool include_PHE(BIGNUM* x, BIGNUM* y1, BIGNUM* y2);

/*
 *@Method 范围相交测试
 *@param BIGNUM* x1 用户DO1持有的数据
 *@param BIGNUM* x2 用户DO1持有的数据
 *@param BIGNUM* y1 用户DO2持有的数据
 *@param BIGNUM* y2 用户DO2持有的数据
 *@return bool true:范围相交; false:范围不相交
 */
bool intersect_PHE(BIGNUM* x1, BIGNUM* x2, BIGNUM* y1, BIGNUM* y2);

/*
 *@Method 求内积
 *@param vector<BIGNUM*> x1 用户DO1持有的数据
 *@param vector<BIGNUM*> y1 用户DO2持有的数据
 *@return BIGNUM* inner_product 内积
 */
BIGNUM* inner_product_PHE(vector<BIGNUM*> x1, vector<BIGNUM*> y1);

/*
 *@Method 求欧氏距离
 *@param vector<BIGNUM*> x1 用户DO1持有的数据
 *@param vector<BIGNUM*> y1 用户DO2持有的数据
 *@return BIGNUM* distance 欧氏距离
 */
BIGNUM* distance_PHE(vector<BIGNUM*> x1, vector<BIGNUM*> y1);

/*
 *@Method 将数据分箱
 *@param vector<BIGNUM*> x 待分箱的数据
 *@param int k 分箱个数
 *@return Bin 分箱结果
 */
vector<Bin> split_PHE(vector<BIGNUM*> x, int k);

/*
 *@Method 计算每个分箱数据出现的频率
 *@param vector<BIGNUM*> x 待分箱的数据
 *@param int k 分箱个数
 *@return vector<BIGNUM*> 分箱频率
 */
vector<BIGNUM*> frequency_PHE(vector<BIGNUM*> x, int k);

#endif //PHE_H
