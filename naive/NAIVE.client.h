#ifndef NAIVE_CLIENT_H
#define NAIVE_CLIENT_H

#include <grpc++/grpc++.h>
#include "NAIVE.grpc.pb.h"
#include "crypto.util.h"
#include "NAIVE.string_append_operator.h"
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
//int maxid = 10;

namespace NAIVE {
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
        
    public:
        Client(std::shared_ptr <Channel> channel, std::string db_path) : stub_(RPC::NewStub(channel)) {
            rocksdb::Options coptions;
            coptions.create_if_missing = true;
            coptions.merge_operator.reset(new rocksdb::StringAppendOperator());
            coptions.use_fsync = true;
            rocksdb::Status status1 = rocksdb::DB::Open(coptions, db_path, &client_db);
        }

        ~Client() {
            std::map<std::string, int>::iterator it1;
            for (it1 = d_cnt.begin(); it1 != d_cnt.end(); ++it1) {
                store(it1->first, std::to_string(it1->second));
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
            std::string tmp;
            rocksdb::Status s;
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

        void read_cnt(std::string w, int& c) {
            std::map<std::string, int>::iterator it;
            it = d_cnt.find(w);
            c = -1;
            if (it != d_cnt.end()) {
                c = it->second;
            } else {
                std::string s = get(w);
                if (s!=""){
                    char* cs = const_cast<char*>(s.c_str());
                    c = atoi(cs);
                    write_cnt(w, c);
                }
            }
        }

        std::string setup(std::string file){
            FILE *fp;
	        fp = fopen(file.c_str(), "r");
   	        if(fp == NULL) {
                perror("open file error");
   	        }
            char s1[100];
            char s2[100];
            int id;
            int count = 0;

            SetupRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<SetupRequestMessage>> writer(stub_->setup(&context, &exec_status));
            std::string keyword, ind, ut, stag, sc, ss1, ss2, wc, e, label, v, enc, sxtag, scf, enc1, enc2;
            std::string last = "";
            int c = 0;
            int i;
            int tmp1 =0;
            std::string tmps;
            AES_KEY key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s%d", s2, &id);
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                keyword  = s2;
                std::cout<<keyword<<" "<<ind<<std::endl;
                if(last ==""){
                    c =1;
                    stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                } else if (last != "" && last != keyword){
                    write_cnt(last, c);
                    c = 1;
                    stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                } else {
                    c++;
                }
                last = keyword;
                sc = std::to_string(10000+c);
                scf = sc+ "0";
                ut = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1); 
                scf = sc+"1";
                ss2 = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                e =  Cutil::Xor("1"+ind, ss2);
                request.set_label(ut);
                request.set_enc(e);
		        writer->Write(request);
            }
            write_cnt(last, c);
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












        int consearch(std::vector<std::string> keywords, std::set<std::string>& result){
            //double start, end, time;
            //start = NAIVE::Cutil::getCurrentTime();
            int c1;
            std::string scf, st;
            SearchRequestMessage request;
            ClientContext context;
            SearchReply reply;
            std::unique_ptr <ClientReaderWriter<SearchRequestMessage, SearchReply>> stream(stub_->consearch(&context));
            AES_KEY key4;
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);

           

           std::mutex writer_lock; 
            auto send_st = [this, &stream, &writer_lock, &request](const int index1, const int index2, const std::string st) {
                request.set_index1(index1);
                request.set_index2(index2);
                request.set_st(st);
                writer_lock.lock();
                stream->Write(request);
                writer_lock.unlock();
            };

            ThreadPool send_st_pool(1);
            std::mutex out_lock; 
            auto st_generation = [this, &key4, &send_st, &send_st_pool, &out_lock](
                       const std::string keyword, const int i, const int j) {
                AES_KEY key5;       
                std::string stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
                Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                std::string scf = std::to_string(10000+j) + "0";
                std::string st = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                send_st_pool.enqueue(send_st, i, j, st);
            };
            ThreadPool st_generation_pool(8);

            std::string keyword;
            int c;
            int sum =0;
            int n = keywords.size();
            std::vector<int> cnts(n);
            for (int i=0; i<n; i++){
                keyword = keywords.at(i);
                read_cnt(keyword, c);
                sum+=c;
                cnts[i] = c;
                for (int j=1; j<=c; j++){
                    st_generation_pool.enqueue(st_generation, keyword, i, j);
                }
            }

            std::vector<std::vector<std::string>> upds(n);
            for (int i = 0; i < n; i++){
                upds[i].resize(cnts.at(i));
            }
            std::mutex vec_lock;           
            auto process_upd = [this, &key4, &keywords, &upds, &vec_lock](
                       const int index1, const int index2, const std::string e) {
                AES_KEY key5;
                std::string keyword = keywords.at(index1);       
                std::string stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
                Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                std::string sc = std::to_string(10000+index2);
                std::string scf = sc+ "1";
                std::string ss2 = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                std::string ss1 =  Cutil::Xor(e, ss2);
                vec_lock.lock();
                upds[index1][index2-1] = ss1;
                vec_lock.unlock(); 
            };

            ThreadPool process_upd_pool(8); 

            int index1, index2;
            std::string e;
            int e_cnt = 0;

            //end = NAIVE::Cutil::getCurrentTime();
            //time = end -start;

            while (stream->Read(&reply)){
                //start = NAIVE::Cutil::getCurrentTime();
                index1 = reply.index1();
                index2 = reply.index2();
                e = reply.eid();
                e_cnt++;
                process_upd_pool.enqueue(process_upd, index1, index2, e);
                if (e_cnt == sum){
                    break;
                }
                //end = NAIVE::Cutil::getCurrentTime();
                //time += (end-start);
            }


            //start = NAIVE::Cutil::getCurrentTime();
            st_generation_pool.join();
            //end = NAIVE::Cutil::getCurrentTime();
            //time += (end-start);

            send_st_pool.join();

            //start = NAIVE::Cutil::getCurrentTime();
            process_upd_pool.join();
            //end = NAIVE::Cutil::getCurrentTime();
            //time += (end - start);
            stream->WritesDone();

            //start = NAIVE::Cutil::getCurrentTime();
            std::string ss1, op, ind;

            std::vector<std::set<std::string>> res(n);
            
            for (int i=0; i<n; i++){
                for (int j=0; j<cnts.at(i); j++){
                    ss1 = upds.at(i).at(j);
                    op = ss1.substr(0, 1);
                    ind = ss1.substr(1, 8);
                    if (op == "1"){
                        res[i].insert(ind);
                    } else if (op == "0"){
                        std::set<std::string>::iterator it = res.at(i).find(ind);
                        if (it != res.at(i).end()){
                            res.at(i).erase(it);
                        }
                    }
                }

               
                if (i==0){
                    result = res.at(i);
                } else {
                    std::set<std::string> tmp(result);
                    //std::set<std::string> tmp2;
                    result.clear();
                    std::set_intersection(res.at(i).begin(), res.at(i).end(),
                          tmp.begin(), tmp.end(),               
                          std::inserter(result, result.end()));
                    //std::set_intersection(res.at(i).begin(), res.at(i).end(), tmp.begin(), tmp.end(), tmp2.begin());
                    //result = tmp2;
                }


            }

            //end = NAIVE::Cutil::getCurrentTime();
            //time += (end - start);
            /*std::ofstream ofile;
            ofile.open("naivesearchtimeclient1.txt", std::ios::app);
            ofile <<cnts.at(0)<<" "<< time*1000 << std::endl;*/




            Status status = stream->Finish();
            if (!status.ok()) {
                std::cout << status.error_details()<< std::endl;
            }

            return 1;

        }





        std::string updatetrace(std::vector<std::pair<std::string, std::string>> updates){ //max the number of documents
            AES_KEY key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            
            UpdateRequestMessage1 request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage1>> writer(stub_->tupdate(&context, &exec_status));

            int id, c;
            std::string opkeyword, keyword, op, ind, stag, sc, scf, ss2, ut, e;
            //std::string ind;
            //std::map<std::string, std::string> db;
            std::string swnum;
            //std::cout<<"qqqqqqqqqqqqqqqqqq"<<std::endl;
            //read_cache("wnum", swnum);
            //std::cout<<"wwwwwwwwwwwwwwwwww"<<std::endl;
            //char* cs = const_cast<char*>(swnum.c_str());
            //int wnum = atoi(cs);
            //std::string ssiz;
            //read_cache("cachesiz", ssiz);
            //cs = const_cast<char*>(ssiz.c_str());
            //int siz = atoi(cs);
            std::pair<std::string, std::string> p;
            for(int i=0; i<updates.size(); i++){
                //读取每个更新条目
                 p = updates.at(i);
                 opkeyword = p.first;
                 op = opkeyword.substr(0, 1);
                 keyword = opkeyword.substr(1);
                 ind = p.second;
                 //std::cout<<op<<" "<<keyword<<" "<<ind<<std::endl;
                stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                read_cnt(keyword, c);
                c++;
                sc = std::to_string(10000+c);
                scf = sc+ "0";
                ut = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1); 
                scf = sc+"1";
                ss2 = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                e =  Cutil::Xor(op+ind, ss2);
                request.set_ut(ut);
                request.set_e(e);
		        writer->Write(request);
                write_cnt(keyword, c);
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


        /* tupdate: 批量更新*/






         

    };


    

} // namespace NAIVE

#endif // NAIVE_CLIENT_H
