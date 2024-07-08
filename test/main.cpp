#include <iostream>
#include <SHE.h>
#include <PHE.h>
#include <openssl/bn.h>
using namespace std;

// 打印花费的时间
void printTime(clock_t start_time,char * desc){
    clock_t end_time = clock();
    double execution_time = ((double) (end_time - start_time)) / CLOCKS_PER_SEC * 1000;
    printf("%s的时间是：%f 毫秒\n",desc, execution_time);
    fflush(stdout);
}

void test_SHE() {
    BIGNUM* a = BN_new();
    BN_set_word(a,123);

    BIGNUM* b = BN_new();
    BN_set_word(b,321);

    generateKeys(20, 80, 80, 1024, 96448);

    // 将明文a加密
    BIGNUM* ciphertext1 = encrypt_SHE(a, sk);

    // 将明文b加密
    BIGNUM* ciphertext2 = encrypt_SHE(b, sk);

    // 测试加解密
    BIGNUM* decrypt_SHEed1 = decrypt_SHE(ciphertext1, sk);

    BIGNUM* decrypt_SHEed2 = decrypt_SHE(ciphertext2, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed1) << endl;

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed2) << endl;

    // 测试同态加法1
    BIGNUM* ciphertext3 = Addition_one(ciphertext1, ciphertext2);

    // 解密密文
    BIGNUM* decrypt_SHEed3 = decrypt_SHE(ciphertext3, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed3) << endl;

    // 测试同态加法2
    BIGNUM* m = BN_new();
    BN_set_word(m, 456);
    BIGNUM* ciphertext4 = Addition_two(ciphertext1, m);

    // 解密密文
    BIGNUM* decrypt_SHEed4 = decrypt_SHE(ciphertext4, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed4) << endl;

    // 测试同态乘法1
    BIGNUM* ciphertext5 = Multiplication_one(ciphertext1, ciphertext2);

    // 解密密文
    BIGNUM* decrypt_SHEed5 = decrypt_SHE(ciphertext5, sk);
    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed5) << endl;

    // 测试同态乘法2
    BIGNUM* ciphertext6 = Multiplication_two(ciphertext1, m);

    // 解密密文
    BIGNUM* decrypt_SHEed6 = decrypt_SHE(ciphertext6, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed6) << endl;
}


void test_PHE() {
    BIGNUM* a = BN_new();
    BN_set_word(a,123);

    BIGNUM* b = BN_new();
    BN_set_word(b,321);

    // 生成公钥和私钥
    InitKeys_PHE(20, 80, 80, 1024, 96448);

    // 将明文a加密
    BIGNUM* ciphertext1 = encrypt_PHE(a, pk);

    // 将明文b加密
    BIGNUM* ciphertext2 = encrypt_PHE(b, pk);

    // 测试加解密
    BIGNUM* decrypt_SHEed1 = decrypt_SHE(ciphertext1, sk);

    BIGNUM* decrypt_SHEed2 = decrypt_SHE(ciphertext2, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed1) << endl;

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed2) << endl;

    // 测试同态加法1
    BIGNUM* ciphertext3 = Addition_one(ciphertext1, ciphertext2);

    // 解密密文
    BIGNUM* decrypt_SHEed3 = decrypt_SHE(ciphertext3, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed3) << endl;

    // 测试同态加法2
    BIGNUM* m = BN_new();
    BN_set_word(m, 456);

    BIGNUM* ciphertext4 = Addition_two(ciphertext1, m);

    // 解密密文
    BIGNUM* decrypt_SHEed4 = decrypt_SHE(ciphertext4, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed4) << endl;

    // 测试同态乘法1
    BIGNUM* ciphertext5 = Multiplication_one(ciphertext1, ciphertext2);

    // 解密密文
    BIGNUM* decrypt_SHEed5 = decrypt_SHE(ciphertext5, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed5) << endl;

    // 测试同态乘法2
    BIGNUM* ciphertext6 = Multiplication_two(ciphertext1, m);

    // 解密密文
    BIGNUM* decrypt_SHEed6 = decrypt_SHE(ciphertext6, sk);

    cout << "decrypt_SHEed: " << BN_bn2dec(decrypt_SHEed6) << endl;

}

// 测试均值计算
void test_avg_PHE() {
    BIGNUM* avg = BN_new();
    long long avg_test = 0;
    // 定义用户持有的数据集合
    vector<BIGNUM*> data_list;
    for (int i = 0; i < 100000; i++) {
        avg_test = avg_test + i + i;
        BN_set_word(avg, i + i);
        data_list.push_back(BN_dup(avg));
    }

    clock_t start = clock();
    // 计算均值
    avg = avg_PHE(data_list);
    cout << "avg: " << BN_bn2dec(avg) << endl;
    printTime(start,"计算均值");

    avg_test /= 100000;
    cout << "avg_test: " << avg_test << endl;
}

// 测试数据比较
void test_compare_PHE() {
    BIGNUM* x1 = BN_new();
    BN_set_word(x1, 139994);

    BIGNUM* x2 = BN_new();
    BN_set_word(x2, 129993);

    clock_t start = clock();

    cout <<  "compare_PHE(x1, x2) = " << compare_PHE(x1, x2) << endl;

    printTime(start,"计算数据比较");
}

// 相等性测试
void test_equal_PHE() {
    BIGNUM* x1 = BN_new();
    BN_set_word(x1, 123);

    BIGNUM* x2 = BN_new();
    BN_set_word(x2, 123);

    clock_t start = clock();
    cout <<  "equal_PHE(x1, x2) = " << equal_PHE(x1, x2) << endl;
    printTime(start,"判断数据相等性");
}

// 测试求最小值
void test_min_PHE() {
    vector<BIGNUM*> datas;

    for (int i = 0; i < 100000; i += 2) {
        BIGNUM* x1 = BN_new();
        BN_set_word(x1, 1000 + i * i);
        datas.push_back(x1);
    }

    for (int i = 1; i < 100000; i += 2) {
        BIGNUM* x1 = BN_new();
        BN_set_word(x1, 500 + i * i);
        datas.push_back(x1);
    }

    clock_t start = clock();
    BIGNUM* min = min_PHE(datas, 0, datas.size() - 1);

    cout << "min: " << BN_bn2dec(min) << endl;

    printTime(start,"计算100000个数据最小值");
}

// 测试求最大值
void test_max_PHE() {
    vector<BIGNUM*> datas;

    for (int i = 0; i < 100000; i += 2) {
        BIGNUM* x1 = BN_new();
        BN_set_word(x1, (long long)i * i + 1000);
        datas.push_back(x1);
    }

    for (int i = 1; i < 100000; i += 2) {
        BIGNUM* x1 = BN_new();
        BN_set_word(x1, (long long)i * i + 500);
        datas.push_back(x1);
    }

    clock_t start = clock();
    BIGNUM* max = max_PHE(datas, 0, datas.size() - 1);

    cout << "max: " << BN_bn2dec(max) << endl;
    printTime(start,"计算100000个数据最大值");
}

// 测试包含关系
void test_include_PHE() {
    BIGNUM* x = BN_new();
    BIGNUM* y1 = BN_new();
    BIGNUM* y2 = BN_new();

    BN_set_word(x, 122);

    BN_set_word(y1, 123);

    BN_set_word(y2, 456);

    clock_t start = clock();
    cout <<  include_PHE(x, y1, y2) << endl;
    printTime(start,"测试包含关系");

}

// 测试范围相交
void test_intersect_PHE() {
    BIGNUM* x1 = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* y1 = BN_new();
    BIGNUM* y2 = BN_new();

    BN_set_word(x1, 10);
    BN_set_word(x2, 15);
    BN_set_word(y1, 110);
    BN_set_word(y2, 170);

    clock_t start = clock();
    cout <<  intersect_PHE(x1, x2, y1, y2) << endl;
    printTime(start,"测试范围相交");
}

// 测试内积
void test_inner_product_PHE() {
    vector<BIGNUM*> x1;
    vector<BIGNUM*> x2;

    // 定义临时变量t
    BIGNUM* t;
    long long test = 0;

    for (int i = 0; i < 100000; i++) {
        t = BN_new();
        BN_set_word(t, 10 + i);
        x1.push_back(t);
        t = BN_new();
        BN_set_word(t, 20 + i);
        x2.push_back(t);
        test = test + (long long)(10 + i) * (20 + i);
    }

    cout << "test: " << test << endl;

    clock_t start = clock();
    BIGNUM* inner_product = inner_product_PHE(x1, x2);
    cout << "inner_product: " << BN_bn2dec(inner_product) << endl;
    printTime(start,"测试内积");
}

// 测试欧氏距离
void test_distance_PHE() {
    vector<BIGNUM*> x1;
    vector<BIGNUM*> x2;

    // 定义临时变量t
    BIGNUM* t;
    long long test = 0;

    for (int i = 0; i < 100; i++) {
        t = BN_new();
        BN_set_word(t, 10 + i);
        x1.push_back(t);
        t = BN_new();
        BN_set_word(t, 20 + i);
        x2.push_back(t);
        test += pow(10, 2);
    }
    cout << "test: " << test << endl;
    cout << "sqrt(test): " << sqrt(test) << endl;

    clock_t start = clock();
    BIGNUM* distance = distance_PHE(x1, x2);
    cout << "distance: " << BN_bn2dec(distance) << endl;
    printTime(start,"欧氏距离");
}

// 测试数据分箱
void test_bin_PHE() {
    vector<BIGNUM*> x;

    BIGNUM* t = BN_new();

    // 插入数据
    for (int i = 1; i < 100000; i++) {
        BN_set_word(t, i + i);
        x.push_back(BN_dup(t));
    }

    int k = 16;
    clock_t start = clock();
    vector<Bin> box = split_PHE(x, k);

    // 输出每个分箱的情况
    for (int i = 0; i < box.size(); i++) {
        cout << "bin " << i << ": " << endl;
        cout << " lower: " << BN_bn2dec(box[i].lower)  << endl;
        cout << " upper: " << BN_bn2dec(box[i].upper) << endl;
        cout << " elements: ";
        for (int j = 0; j < box[i].elements.size(); j++) {
            cout << BN_bn2dec(box[i].elements[j]) << " ";
        }
        cout << endl;
        cout << "----------------" << endl;
    }
    printTime(start,"测试数据分箱");
}

// 测试频率计算
void test_frequency_PHE() {
    vector<BIGNUM*> x;

    BIGNUM* t = BN_new();

    // 插入数据
    for (int i = 1; i < 100000; i++) {
        BN_set_word(t, i + i);
        x.push_back(BN_dup(t));
    }

    int k = 16;

    clock_t start = clock();
    vector<BIGNUM*> frequency = frequency_PHE(x, k);

    for (int i = 0; i < frequency.size(); i++) {
        cout << BN_bn2dec(frequency[i]) << " ";
    }

    cout << endl;
    printTime(start,"计算频率");
}

int main() {
    // test_SHE();
    // test_PHE();
    // test_avg_PHE();
    // test_compare_PHE();
    // test_equal_PHE();
    // test_min_PHE();
    // test_max_PHE();
    // test_include_PHE();
    // test_intersect_PHE();
    // test_inner_product_PHE();
    // test_distance_PHE();
    // test_bin_PHE();
    // test_frequency_PHE();

    return 0;
}
