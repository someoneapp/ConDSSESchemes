#ifndef CQDSSE_CLIENT_H
#define CQDSSE_CLIENT_H

#include <grpc++/grpc++.h>
#include "CQDSSE.grpc.pb.h"
#include "crypto.util.h"
#include "CQDSSE.string_append_operator.h"
#include "thread_pool.hpp"
#include <thread>
#include <utility>
#include<iostream>
#include<fstream>
#include<iomanip>
#include <bitset>

#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>

using namespace CryptoPP;

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReaderInterface;
using grpc::ClientWriterInterface;
using grpc::ClientAsyncResponseReaderInterface;
using grpc::Status;
using grpc::ClientReaderWriter;


byte k_s[17] = "0123456789abcdef";
byte iv_s[17] = "0123456789abcdef";

byte k_t[17] = "1gjhg45jkgabcdef";

byte k_g[17] = "asdfvhjlqdapvskl";

byte k_h1[17] = "qwertyuioplkjhgf";
byte iv_h1[17] = "qazxsdcvfgbnhjkl";

byte k_h2[17] = "9w7r5y0iog43jh2f";
byte iv_h2[17] = "2345678909876543";


byte k_i[17] = "sdfgregreghthrth";
byte k_z[17] = "gewgrgwrgwgerhgt";

byte k_x[17] = "8w8687ug90970909";

namespace CQDSSE {
    #if __GNUC__
    #define ALIGN(n)      __attribute__ ((aligned(n))) 
    #elif _MSC_VER
    #define ALIGN(n)      __declspec(align(n))
    #else
    #define ALIGN(n)
    #endif

    class Client {
    private:
        std::unique_ptr <RPC::Stub> stub_;
        rocksdb::DB *client_db;
        std::map <std::string, int> d_cnt;
        std::map <std::string, std::string> st_map;
        int len_bs;
        int a;
        
    public:
        Client(std::shared_ptr <Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)) {
            len_bs=0;
            a=0;
            rocksdb::Options coptions;
            coptions.create_if_missing = true;
            coptions.merge_operator.reset(new rocksdb::StringAppendOperator());
            coptions.use_fsync = true;
            rocksdb::Status status1 = rocksdb::DB::Open(coptions, db_path, &client_db);
        }

        ~Client() {
            std::map<std::string, int>::iterator it1;
             std::map<std::string, std::string>::iterator it2;
            for (it1 = d_cnt.begin(), it2=st_map.begin(); it1 != d_cnt.end(), it2 != st_map.end(); ++it1, ++it2) {
                store(it1->first, it2->second+std::to_string(it1->second));
            }
            client_db->Flush(rocksdb::FlushOptions());
            delete client_db;

            std::cout << "Bye~ " << std::endl;
        }

         int store(const std::string k, const std::string v) {
            rocksdb::Status s;
            s = client_db->Delete(rocksdb::WriteOptions(), k);
            s = client_db->Put(rocksdb::WriteOptions(), k, v);
            if (s.ok()) return 0;
            else return -1;
        }



        std::string get(const std::string k) {
            rocksdb::Status s;
            std::string tmp;
            s = client_db->Get(rocksdb::ReadOptions(), k, &tmp);
            if (s.ok()) return tmp;
            else return "";
        }


        std::string write_cnt(std::string w, int c) {
            {
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                d_cnt[w] = c;
            }
            return "OK";
        }

         std::string write_st(std::string k, std::string v) {
            {
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                st_map[k] = v;
            }
            return "OK";
        }


        void read_cnt(std::string w, int& c) {
            std::map<std::string, int>::iterator it;
            it = d_cnt.find(w);
            c = -1;
            if (it != d_cnt.end()) {
                c = it->second; 
            } else {
                std::string s = get(w);
                if (s!=""){
                    std::string st_str = s.substr(0, 16);
                    write_st(w, st_str);
                    std::string c_str = s.substr(16);
                    char* cs = const_cast<char*>(c_str.c_str());
                    c = atoi(cs);
                    write_cnt(w, c);
                }
            }
        }

        void read_st(std::string k, std::string& v) {
            std::map<std::string, std::string>::iterator it;
            it = st_map.find(k);
            v= "";
            if (it != st_map.end()) {
                v = it->second;
            } else {
                std::string s = get(k);
                if (s!=""){
                    v = s.substr(0, 16);
                    write_st(k, v);
                    std::string c_str = s.substr(16);
                    char* cs = const_cast<char*>(c_str.c_str());
                    int c = atoi(cs);
                    write_cnt(k, c);
                }
            }
            //c = -1;
        }

       


        std::string setupcq(std::string file, int d_num, int w_num){ 
            FILE *fp;
	        fp = fopen(file.c_str(), "r");
   	        if(fp == NULL) {
                perror("open file error");
   	        }
            char s1[100];
            char s2[100];
            int id;
            int count = 0;
            int a = log(w_num)/log(2);
            a=a+1;
            int len_bs = d_num*a; // the length of the bit string to represent a document
            store("len_bs111", std::to_string(len_bs));
            store("a111", std::to_string(a));
            std::string n(len_bs+1, '0');
            n[0] = '1';
            n = n + "b";
            Integer int_n(n.c_str());


            SetupRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<SetupRequestMessage>> writer(stub_->setup(&context, &exec_status));
            std::string keyword, ut, e;
            std::string last = "";
            int c = 0;
            int i, b;
            int tmp1 =0;
            std::string oldst, st, enc_oldst, kw, kw2, kwc, sc, ssk;
            AES_KEY key1, key2, keyw;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h2, 128, &key2);
            Integer sk;
            AutoSeededRandomPool prng;
            byte rand[16];
            AutoSeededRandomPool rnd;
            Integer int_sum("0");
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s %d", s2, &id);
                keyword  = s2;
                std::cout<<keyword<<" "<<id<<std::endl;
                std::string bsid(len_bs, '0');
                b = a*(d_num-id)+a-1;
                bsid[b] = '1';
                bsid= bsid + "b";
                Integer int_id(bsid.c_str());
                if (last == ""){
                    c = 1;
                    kw = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                    rnd.GenerateBlock(rand, 16);
                    oldst = std::string((const char*)rand, 16);
                    rnd.GenerateBlock(rand, 16);
                    st = std::string((const char*)rand, 16);
                    ut = Cutil::H1(kw+st);
                    enc_oldst = Cutil::Xor(oldst, Cutil::H2(kw+st));
                    kw2 = Cutil::F_aesni(&key2, keyword.c_str(), keyword.length(), 1);
                    Cutil::sk_generate(kw2, c, len_bs, int_n, sk);
                    e = Cutil::henc(sk, int_id, int_n); 
                    last = keyword;

                }  else if (last != "" && keyword != last){
                    write_cnt(last, c);
                    write_st(last, st);
                    c = 1;
                    kw = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                    rnd.GenerateBlock(rand, 16);
                    oldst = std::string((const char*)rand, 16);
                    rnd.GenerateBlock(rand, 16);
                    st = std::string((const char*)rand, 16);
                    ut = Cutil::H1(kw+st);
                    enc_oldst = Cutil::Xor(oldst, Cutil::H2(kw+st));
                    kw2 = Cutil::F_aesni(&key2, keyword.c_str(), keyword.length(), 1);
                    Cutil::sk_generate(kw2, c, len_bs, int_n, sk); 
                    e = Cutil::henc(sk, int_id, int_n);
                    last = keyword;
                } else {
                    c++;
                    oldst = st;
                    rnd.GenerateBlock(rand, 16);
                    st = std::string((const char*)rand, 16);
                    ut = Cutil::H1(kw+st);
                    enc_oldst = Cutil::Xor(oldst, Cutil::H2(kw+st));
                    Cutil::sk_generate(kw2, c, len_bs, int_n, sk);  
                    e = Cutil::henc(sk, int_id, int_n);

                }
                request.set_label(ut);
                request.set_cst(enc_oldst);
                request.set_enc(e);
                writer->Write(request);
            }

            request.set_label("len_bs");
            request.set_enc(std::to_string(len_bs));
            writer->Write(request);
            write_cnt(last, c);
            write_st(last, st);
            fclose(fp);
            writer->WritesDone();
            Status status = writer->Finish();
            if (status.ok()) {
                std::string log = "DB Setup completed";
                std::cout << log <<std::endl;
                return "OK";
            } else {
                return "FALSE";
            }
        }












        int consearch(std::vector<std::string> keywords, std::unordered_set<std::string>& sresult){

            //double start, end, time;
            //start = Cutil::getCurrentTime();
            std::string st, keyword, kw;
            int c;

            AES_KEY key1, key2;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h2, 128, &key2);


            SearchRequestMessage request;
            ClientContext context;
            SearchReply reply;
            std::unique_ptr <ClientReaderWriter<SearchRequestMessage, SearchReply>> stream(stub_->consearch(&context));
            //end = Cutil::getCurrentTime();
            //time = end - start;

            for (int i=0; i<keywords.size(); i++){
                //start = Cutil::getCurrentTime();
                keyword = keywords.at(i);
                kw = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                read_st(keyword, st);
                read_cnt(keyword, c);
                request.set_kw(kw);
                request.set_st(st);
                request.set_c(c);
                //end = Cutil::getCurrentTime();
                //time += end - start;

                stream->Write(request); 
            }

            request.set_kw("");
            stream->Write(request);
            //start = Cutil::getCurrentTime();
            if(len_bs==0){
                std::string slen= get("len_bs111");  
                //std::cout<<"slen: "<<slen<<std::endl;
                char* cs = const_cast<char*>(slen.c_str());
                len_bs = atoi(cs);
                std::string sa= get("a111");
                cs = const_cast<char*>(sa.c_str());
                a = atoi(cs);
            }
            std::string sn(len_bs+1, '0');
            sn[0] = '1';
            sn = sn + "b";
            Integer int_n(sn.c_str());
            //end = Cutil::getCurrentTime();
            //time += (end - start);
            stream->Read(&reply);
            //start = Cutil::getCurrentTime();
            std::string ssum = reply.sum();
            std::string kw2;
            Integer sk;
            Integer sksum("0");
            for (int i=0; i<keywords.size(); i++){
                keyword = keywords.at(i);
                read_cnt(keyword, c);
                for (int j=1; j<=c; j++){
                    kw2 = Cutil::F_aesni(&key2, keyword.c_str(), keyword.length(), 1);
                    Cutil::sk_generate(kw2, j, len_bs, int_n, sk);
                    sksum = (sksum + sk)%int_n;
                }
            }
            Integer int_ssum(ssum.c_str());
            Integer bs = (int_ssum-sksum)%int_n;
            unsigned int bitcnt = bs.BitCount();
            int k=0;
            unsigned long t;
            for (int i=0; i< bitcnt; i+=a){
                //std::string testbs ="";
                k++;
                t = bs.GetBits(i, a);//0, 1, 2; 3, 4, 5; 6, 7, 8; 9, 10, 11; 12, 13, 14; 15, 16, 17; 18, 19, 20; 21, 22, 23; 24, 25, 26; 27, 28, 29
                if (t==keywords.size()){
                    sresult.insert(std::to_string(k));
                }
            }
            //end = Cutil::getCurrentTime();
            //time += (end-start);
            //std::ofstream OsWrite1("cqsearchtimeclient.txt",std::ofstream::app);
            //OsWrite1<<time *1000<<std::endl;


           
            return 1;

        }



        std::string updatetrace(std::vector<std::pair<std::string, int>> updates, int d_num){ //max the number of documents
            if(len_bs==0){
                std::string slen= get("len_bs111");  
                //std::cout<<"slen: "<<slen<<std::endl;
                char* cs = const_cast<char*>(slen.c_str());
                len_bs = atoi(cs);
                std::string sa= get("a111");
                cs = const_cast<char*>(sa.c_str());
                a = atoi(cs);
            }
            std::string n(len_bs+1, '0');
            n[0] = '1';
            n = n + "b";
            Integer int_n(n.c_str());


            AES_KEY key1, key2, keyw;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h2, 128, &key2);
            
            UpdateRequestMessage1 request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage1>> writer(stub_->tupdate(&context, &exec_status));

            int b, id, c;
            std::string opkeyword, keyword, op, st, oldst, kw, kw2, enc_oldst, ut, e;
            std::pair<std::string, int> p;

            Integer sk;
            AutoSeededRandomPool prng;
            byte rand[16];
            AutoSeededRandomPool rnd;
            Integer int_sum("0");

            for(int i=0; i<updates.size(); i++){
                 p = updates.at(i);
                 opkeyword = p.first;
                 op = opkeyword.substr(0, 1);
                 keyword = opkeyword.substr(1);
                 id = p.second;
                 //std::cout<<op<<" "<<keyword<<" "<<id<<std::endl;
                 kw = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                 kw2 = Cutil::F_aesni(&key2, keyword.c_str(), keyword.length(), 1);
                std::string bsid(len_bs, '0');
                b = a*(d_num-id)+a-1;
                bsid[b] = '1';
                bsid= bsid + "b";
                Integer int_id(bsid.c_str());
                if (op=="0"){
                    int_id = int_n-int_id;
                }
                read_cnt(keyword, c);
                if (c==-1){
                    c=1;
                    rnd.GenerateBlock(rand, 16);
                    oldst = std::string((const char*)rand, 16);   
                } else {
                    c++;
                    read_st(keyword, st);
                    oldst = st;
                }

                rnd.GenerateBlock(rand, 16);
                st = std::string((const char*)rand, 16);
                ut = Cutil::H1(kw+st);
                enc_oldst = Cutil::Xor(oldst, Cutil::H2(kw+st));
                Cutil::sk_generate(kw2, c, len_bs, int_n, sk);
                e = Cutil::henc(sk, int_id, int_n); 
                request.set_label(ut);
                request.set_cst(enc_oldst);
                request.set_enc(e);
                writer->Write(request);
                write_cnt(keyword, c);
                write_st(keyword, st);
            } 
            writer->WritesDone();
            Status status = writer->Finish();
            if (status.ok()) {
                std::string log = "DB tupdate completed";
                std::cout << log <<std::endl;
                return "OK";
            } else {
                return "FALSE";
            }
        }


        std::string prepare(int d_num, int w_num){
            a = log(w_num)/log(2);
            a=a+1;
            //a=1;
            len_bs = d_num*a;
            store("len_bs111", std::to_string(len_bs));
            store("a111", std::to_string(a));
            SetupRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<SetupRequestMessage>> writer(stub_->setup(&context, &exec_status));
            request.set_label("len_bs");
            request.set_enc(std::to_string(len_bs));
            writer->Write(request);
            writer->WritesDone();
            Status status = writer->Finish();
            if (status.ok()) {
                std::string log = "DB Prepare completed";
                std::cout << log <<std::endl;
                return "OK";
            } else {
                return "FALSE";
            }
        }


    };

} // namespace CQDSSE

#endif // CQDSSE_CLIENT_H
