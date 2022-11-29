
#ifndef SERVER_STORAGE_H
#define SERVER_STORAGE_H

#include <grpc++/grpc++.h>
#include "crypto.util.h"
#include "HBS.string_append_operator.h"
#include <algorithm>
#include <string>
#include <utility>
#include <cmath>
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>

#include "thread_pool.hpp"

using namespace CryptoPP;


byte k_s[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";

byte k_t[17] = "1gjhg45jkgabcdef";

byte k_g[17] = "asdfvhjlqdapvskl";

byte k_h1[17] = "qwertyuioplkjhgf";
byte iv_h1[17] = "qazxsdcvfgbnhjkl";

byte k_h2[17] = "9w7r5y0iog43jh2f";
byte iv_h2[17] = "2345678909876543";

//int maxid = 10;

namespace STORAGE {
    #if __GNUC__
    #define ALIGN(n)      __attribute__ ((aligned(n))) 
    #elif _MSC_VER
    #define ALIGN(n)      __declspec(align(n))
    #else
    #define ALIGN(n)
    #endif

    class Client {
    private:
        rocksdb::DB *server_db1;
        rocksdb::DB *server_db2;
        std::map <std::string, int> d_cnt;
        std::map <std::string, int> w_flag;
        int maxid;
        
    public:
        Client(std::string db_path1, std::string db_path2) {
            rocksdb::Options options;
            options.create_if_missing = true;
            options.max_background_compactions = 8;
            options.max_subcompactions = 4;
            options.compaction_style=rocksdb::kCompactionStyleLevel;
            options.level_compaction_dynamic_level_bytes=true; 
            options.compression_per_level = {rocksdb::kNoCompression, rocksdb::kNoCompression, rocksdb::kNoCompression, rocksdb::kLZ4Compression, rocksdb::kLZ4Compression, rocksdb::kLZ4Compression};
            options.compression=rocksdb::kLZ4Compression;
            options.compression_opts.level=4;
            options.bottommost_compression=rocksdb::kZSTD;
            options.bottommost_compression_opts.max_dict_bytes = 1 << 14;  
            //options.bottommost_compression_opts.zstd_max_train_bytes=1 << 18;
            options.bottommost_compression_opts.level=10;
            options.bottommost_compression_opts.enabled=true;

            rocksdb::BlockBasedTableOptions table_options;
            table_options.block_size=16*1024;
            table_options.format_version = 4;
            table_options.index_block_restart_interval = 16;
            table_options.enable_index_compression=false;
            options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
            rocksdb::Status s1 = rocksdb::DB::Open(options, db_path1, &server_db1);
            if (!s1.ok()) {
                std::cerr << "open ssdb1 error:" << s1.ToString() << std::endl;
            }
            rocksdb::Status s2 = rocksdb::DB::Open(options, db_path2, &server_db2);
            if (!s2.ok()) {
                std::cerr << "open ssdb2 error:" << s2.ToString() << std::endl;
            }
        }

        ~Client() {
            server_db1->Flush(rocksdb::FlushOptions());
            server_db2->Flush(rocksdb::FlushOptions());
            delete server_db1;
            delete server_db2;

            std::cout << "Bye~ " << std::endl;
        }

        static int store(rocksdb::DB *&db, const std::string ut, const std::string e) {
            rocksdb::Status s;
            rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
            {
                s = db->Put(write_option, ut, e);

            }
            assert(s.ok());
            if (s.ok()) return 0;
            else {
                return -1;
            }
        }


        int store1(const std::string k, const std::string v) {

            rocksdb::Status s = server_db1->Put(rocksdb::WriteOptions(), k, v);

            if (s.ok()) return 0;

            else return -1;

        }

        int store2(const std::string k, const std::string v) {

            rocksdb::Status s = server_db2->Put(rocksdb::WriteOptions(), k, v);

            if (s.ok()) return 0;

            else return -1;

        }



        int hdxt_storage(std::string file, int max) {
            FILE *fp;
                fp = fopen(file.c_str(), "r");
                if(fp == NULL) {
                perror("open file error");
                }
            char s1[1000];
            char s2[1000];
            int id;
            std::string keyword, ind, last;

            AES_KEY key1, key2, key3, key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h2, 128, &key2);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key3);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            std::string wid, ut, e, ss1, ss2, label, v, enc;
	    byte rand1[16];
	     byte rand2[16];

            AutoSeededRandomPool rnd;

            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s%d", s2, &id);
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                keyword  = s2;
                std::cout<<keyword<<" "<<id<<std::endl;
                wid = keyword+ind;
                ut = Cutil::F_aesni(&key4, wid.c_str(), wid.length(), 1);
                ss1 = "1" + ind;
                ss2 = Cutil::F_aesni(&key3, wid.c_str(), wid.length(), 1);
                e =  Cutil::Xor(ss1, ss2);
               store1(ut, e);

                if (last != keyword){
                    for (int i=1; i<=max; i++){
			        rnd.GenerateBlock(rand1, 16);
                    label = std::string((const char*)rand1, 16);
		            rnd.GenerateBlock(rand2, 16);
                    enc = std::string((const char*)rand2, 16);
                    store2(label, enc);
                    }
                    last = keyword;
                }

            }

        }



         int ibtree_storage(int d_num, int w_num) {
            std::string index, leftchild, rightchild, remain;
            std::string element, link;
            int n = d_num;
            int r = 0;
            int k;
            int s = n+r;
            int cnt =0;
            int flag;
            size_t len = 8*w_num;
            byte rand[len];

            AutoSeededRandomPool rnd;
            while (s >= 1){
                std::cout <<"s: " <<s<<std::endl;
                std::cout <<"cnt: " <<cnt<<std::endl;
                for (int i=0; i<n; i++){
                   if (cnt == 0){
                        index = std::to_string(cnt) + "|" + std::to_string(10000000+i);
                        link = std::to_string(cnt) + "|" + std::to_string(10000000+i+1);
                    } else {
                        index = std::to_string(cnt) + "|" + std::to_string(i);
                    }
                    std::cout<<index<<std::endl;
                    if (cnt !=0 && i<n-1){
                        leftchild = std::to_string(cnt-1)+"|"+std::to_string(k);
                        rightchild = std::to_string(cnt-1)+"|"+std::to_string(k+1);
                        k += 2;
                    } else if (cnt !=0 && i==n-1 && flag ==0){
                        leftchild = std::to_string(cnt-1)+"|"+std::to_string(k);
                        rightchild = std::to_string(cnt-1)+"|"+std::to_string(k+1);
                    } else if (cnt !=0 && i==n-1 && flag ==1){
                        leftchild = std::to_string(cnt-1)+"|"+std::to_string(k);
                        rightchild = remain;
                        remain ="";
                    }

                    rnd.GenerateBlock(rand, len);
                    element = std::string((const char*)rand, len);

                    //store_token_pool.enqueue(store_tokens, index, element+leftchild+"|"+rightchild);
                    if(cnt==0){
                        store1(index, element+link);
                    } else {
                        store1(index, element+leftchild+"|"+rightchild);
                    }
                }
                if (s ==1){
                    break;
                }
                r = s - (s/2)*2;
                if (r != 0 && remain == ""){ 
                    remain = "level" + std::to_string(cnt)+std::to_string(n-1);
                    flag =0;
                }else if (r == 0 && remain != ""){
                    flag =1;
                }
                n = s/2; 
		        s=n+r; 
                k =0;
                cnt++;
            }

        }


        
        
        
        
        
        int cnffilter_storage(std::string file){
            FILE *fp;
	        fp = fopen(file.c_str(), "r");
   	        if(fp == NULL) {
                perror("open file error");
   	        }
            char s1[1000];
            char s2[1000];
            int id;
            int lastid = 0;
            std::string w1, w2, ind;
            std::vector <std::string> keywords;
            AES_KEY key1, key3, key4;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key3);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);

            std::string w1w2id, ut, tag, e, label;
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%d %s", &id, s2);
                if (lastid == 0){
                    ind = std::to_string(100000000 + id);
                    ind = ind.substr(1, 8);
                    lastid = id;
                    w1  = s2;
                    keywords.push_back(w1);
                } else if (id !=lastid){
                    ind = std::to_string(100000000 + id);
                    ind = ind.substr(1, 8);
                    lastid = id;
                    keywords.clear();
                    w1  = s2;
                    keywords.push_back(w1);
                } else {
                    w1  = s2;
                    std::cout<<id<<" "<<w1<<" "<<keywords.size()<<std::endl;
                    for (int i=0; i<keywords.size(); i++){
                        w2 = keywords[i];
                        w1w2id = w1+w2+ind;
                        ut = Cutil::F_aesni(&key4, w1w2id.c_str(), w1w2id.length(), 1);
                        tag = Cutil::F_aesni(&key3, w1w2id.c_str(), w1w2id.length(), 1);
                        e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind);
                        store1(ut, tag+e);
                        w1w2id = w2+w1+ind;
                        ut = Cutil::F_aesni(&key4, w1w2id.c_str(), w1w2id.length(), 1);
                        tag = Cutil::F_aesni(&key3, w1w2id.c_str(), w1w2id.length(), 1);
                        store1(ut, tag+e);
                        w1w2id = w1+w2+ind;
                        label = Cutil::F_aesni(&key1, w1w2id.c_str(), w1w2id.length(), 1);
                        store2(label, "");
                        w1w2id = w2+w1+ind;
                        label = Cutil::F_aesni(&key1, w1w2id.c_str(), w1w2id.length(), 1);
                        store2(label, "");
                    }
                    keywords.push_back(w1);
                } 
                //
            
            }

            

        }





    int iex_storage(std::string file){
            FILE *fp;
	        fp = fopen(file.c_str(), "r");
   	        if(fp == NULL) {
                perror("open file error");
   	        }
            char s1[1000];
            char s2[1000];
            int id;
            int lastid = 0;
            std::string w1, w2, ind;
            std::vector <std::string> keywords;
            AES_KEY key1, key3, key4;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key3);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);

	        std::string w1id, w1w2id, ut, tag, e, label;
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%d %s", &id, s2);
		        std::cout<<id<<std::endl;
                if (lastid == 0){
                    ind = std::to_string(100000000 + id);
                    ind = ind.substr(1, 8);
                    lastid = id;
                    w1  = s2;
                    w1id = w1+ind;
                    ut = Cutil::F_aesni(&key4, w1.c_str(), w1.length(), 1);
                    tag = Cutil::F_aesni(&key3, w1id.c_str(), w1id.length(), 1);
                    e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind+tag);
                    store1(ut, e);
                    keywords.push_back(w1);
                } else if (id !=lastid){
                    ind = std::to_string(100000000 + id);
                    ind = ind.substr(1, 8);
                    lastid = id;
                    keywords.clear();
                    w1  = s2;
                    //compute_token_pool.enqueue(compute_tokens, w1, "", ind, 0);
		            w1id = w1+ind;
                    ut = Cutil::F_aesni(&key4, w1.c_str(), w1.length(), 1);
                    tag = Cutil::F_aesni(&key3, w1id.c_str(), w1id.length(), 1);
                    e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind+tag);
                    store1(ut, e);
                    keywords.push_back(w1);
                } else {
                    w1  = s2;
                    w1id = w1+ind;
                    ut = Cutil::F_aesni(&key4, w1.c_str(), w1.length(), 1);
                    tag = Cutil::F_aesni(&key3, w1id.c_str(), w1id.length(), 1);
                    e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind+tag);
                    store1(ut, e);
		    for (int i=0; i<keywords.size(); i++){
                        w2 = keywords[i];
                        //compute_token_pool.enqueue(compute_tokens, w1, w2, ind, 1);
                        w1w2id = w1+w2+ind;
                        w1id = w1+ind;
                        label = Cutil::F_aesni(&key1, w1w2id.c_str(), w1w2id.length(), 1);
                        tag = Cutil::F_aesni(&key3, w1id.c_str(), w1id.length(), 1);
                        e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind+tag);
                        store2(label, e);
                        w1w2id = w2+w1+ind;
                        w1id = w2+ind;
                        label = Cutil::F_aesni(&key1, w1w2id.c_str(), w1w2id.length(), 1);
                        tag = Cutil::F_aesni(&key3, w1id.c_str(), w1id.length(), 1);
                        e =  Cutil::CTR_AESEncryptStr(k_h2, iv_s, ind+tag);
                        store2(label, e);
			//compute_token_pool.enqueue(compute_tokens, w2, w1, ind, 1);
                    }
                    keywords.push_back(w1);
                } 
                //
            
            }

            /*compute_token_pool.join();
            store_token_pool.join();*/

        }



        int blindseer_storage(int d_num, int w_num) {
            //process d_num = 10^几次
            std::string index, leftchild, rightchild, remain;
            std::string element;
            //只要读取document

            std::mutex write_lock;
            auto store_tokens = [this, &write_lock](std::string index, std::string element){
                //request.set_label(label);
                write_lock.lock();
                store(server_db1, index, element);
                write_lock.unlock();
            };
            ThreadPool store_token_pool(1); 

            int n = d_num;
            int cnt =0;
            int r=0;
            int t =0;
            int s = n;
            std::string children = "|";
            while(s>=1){
                std::cout<<"s: "<<s<<std::endl;
                for (int i=0; i<n; i++){
                    index = std::to_string(cnt) + std::to_string(i);
                    if (cnt > 0){
                        children = "|";
                        for (int k=0; k<10; k++){
                            children = children + std::to_string(cnt-1)+std::to_string(t+k) + "|";
                            //0-9
                            //10-19
                        }
                        t+=10;  
                    } else {
                        children ="";
                    }
                    element = "";
                    for (int j=0; j<w_num*29; j++){
                        element += "0";
                    }
                    store_token_pool.enqueue(store_tokens, index, element+children);
                }

                if (r!=0){
                    index = std::to_string(cnt) + std::to_string(n);
                    children = "|";
                    for (int i=0; i<r; i++){
                        children = children + std::to_string(cnt-1)+std::to_string(t+i)+"|";
                    }
                    element = "";
                    for (int j=0; j<w_num*29; j++){
                        element += "0";
                    }                 
                    store_token_pool.enqueue(store_tokens, index, element+children);
                }

                if (s==1){
                    break;
                }

                r = s - (s/10)*10; // 下一层的剩余节点（< 10） 这r个节点会在下层形成一个parent node
                n= n/10; //下一层的有10个孩子的节点
                if (r == 0){
                    s = n;
                } else {
                    s = n+1;
                }
                // s 是下一层的节点数目
                cnt ++;
                t =0;
            }

            store_token_pool.join();

        }






        int fbdssecq_storage(std::string file, int d_num, int w_num){
            FILE *fp;
                fp = fopen(file.c_str(), "r");
                if(fp == NULL) {
                perror("open file error");
                }
            char s1[1000];
            char s2[1000];

            /*int a = log(w_num+1)/log(2);
            std::cout<<"a: "<<a<<std::endl;
            int len_bs = d_num*a; // the length of the bit string to represent a document
            std::cout<<"len_bs: "<<len_bs<<std::endl;
            std::string n(len_bs+1, '0');
            n[0] = '1';
            n = n + "b";
            Integer int_n(n.c_str());
            std::cout<<"111111111111111111"<<std::endl;*/
            int id;
            std::string ind;
            std::string keyword;
            std::string last = "";
            int c =0;
            /*Intege i("111111111111b");
            SecByteBlock b(i.ByteCount());
            i.Encode(b, b.size());
            r.GenerateRandom(NullRNG(), MakeParameters("BitLength", 4)(Name::Seed(), ConstByteArrayParameter(b)));
            std::cout<<r<<std::endl;*/





            AES_KEY key1, key2, key3, key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h2, 128, &key2);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key3);
            //Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key4);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            std::string hbsid, oldwc, wc, ildwc, oldst, st, ut, enc_oldst, sk, e;
            //int b;
            /*std::string bsid(len_bs, '0');

            int b = a*(d_num-10300)+a-1;

            bsid[b] = '1';

            bsid= bsid + "b";

            std::cout<<"33333333333333333333333333333333333333"<<std::endl;

            //std::string hbsid = Cutil::bittohex(hbsid);

            Integer int_id(bsid.c_str());

            Integer sk, res;
            AutoSeededRandomPool prng;
            Integer qq;
		    qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;
            qq.Randomize(prng, len_bs);
            std::cout<<Cutil::Inttostring(qq).length()<<std::endl;
            e = Cutil::henc(qq, int_id, int_n);
            std::cout<<"ww   "<<e.length()<<std::endl;*/
             byte rand[88662];
            AutoSeededRandomPool rnd;

            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s %d", s2, &id);
                keyword = s2;
                std::cout<<keyword<<" "<<id<<std::endl;
                std::cout<<"222222222222222222222222222222"<<std::endl;
                if (keyword != last){
                    c = 1;
                    //compute_token_pool.enqueue(compute_tokens, keyword, id, c);
                     std::cout<<"444444444444444444444444444444444444444444444444"<<std::endl;
                     wc = keyword+std::to_string(c);
                     oldwc = "000000000";
                     oldst = Cutil::F_aesni(&key4, oldwc.c_str(), oldwc.length(), 1);
                     st = Cutil::F_aesni(&key4, wc.c_str(), wc.length(), 1);
                     ut = Cutil::H1(st);
                     enc_oldst = Cutil::Xor(st, Cutil::H2(oldst));
                     //sk = Cutil::F_aesni(&key3, wc.c_str(), wc.length(), 1);
                    /* Integer res;
                     Cutil::Bytestoint(wc, res);
                    SecByteBlock b(res.ByteCount());
                    res.Encode(b, b.size());
                    Integer sk;
                    sk.GenerateRandom(NullRNG(), MakeParameters("BitLength", len_bs)(Name::Seed(), ConstByteArrayParameter(b)));
                     std::cout<<Cutil::Inttostring(sk).length()<<std::endl;
                     e = Cutil::henc(sk, int_id, int_n);
                     std::cout<<e.length()<<std::endl;
                     std::cout<<"6666666666666666666666666"<<std::endl;*/
                    rnd.GenerateBlock(rand, 88662);
                    e = std::string((const char*)rand, 88662);

                     store1(ut, enc_oldst+e);
                     std::cout<<"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"<<std::endl;
                    last = keyword;
                } else {
                    c++;
                    //compute_token_pool.enqueue(compute_tokens, keyword, id, c);
                     /*std::string bsid(len_bs, '0');
                     b = a*(d_num-id)+a-1;
                     bsid[b] = '1';
                     bsid= bsid + "b";
                     //std::string hbsid = Cutil::bittohex(hbsid);
                     std::cout<<"777777777777777777777777777777"<<std::endl;
                     Integer int_id(bsid.c_str());*/
                     std::cout<<"8888888888888888888888888888888888888888"<<std::endl;
                     wc = keyword+std::to_string(c);
                     oldwc = keyword+std::to_string(c-1);
                     oldst = Cutil::F_aesni(&key4, oldwc.c_str(), oldwc.length(), 1);
                     st = Cutil::F_aesni(&key4, wc.c_str(), wc.length(), 1);
                     ut = Cutil::H1(st);
                     enc_oldst = Cutil::Xor(st, Cutil::H2(oldst));
                     //sk = Cutil::F_aesni(&key3, wc.c_str(), wc.length(), 1);
                     /*Integer res;
                     Cutil::Bytestoint(wc, res);
                    SecByteBlock b(res.ByteCount());
                        res.Encode(b, b.size());
                    Integer sk;
                    sk.GenerateRandom(NullRNG(), MakeParameters("BitLength", len_bs)(Name::Seed(), ConstByteArrayParameter(b)));
                     std::cout<<Cutil::Inttostring(sk).length()<<std::endl;
                     e = Cutil::henc(sk, int_id, int_n);
                      std::cout<<e.length()<<std::endl;
                     std::cout<<"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"<<std::endl;*/
                    rnd.GenerateBlock(rand, 88662);
                    e = std::string((const char*)rand, 88662);

                     store1(ut, enc_oldst+e);
                     std::cout<<"wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"<<std::endl;

                }

            }

        }





        
















        
        

        

    };

} // namespace server.storage

#endif // SERVER_STORAGE_H
