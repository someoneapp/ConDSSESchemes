#ifndef HDXTSU_CLIENT_H
#define HDXTSU_CLIENT_H

#include <grpc++/grpc++.h>
#include "HDXTSU.grpc.pb.h"
#include "crypto.util.h"
#include "HDXTSU.string_append_operator.h"
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

namespace HDXTSU {
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
        rocksdb::DB *client_cache;
        std::map <std::string, int> d_cnt;
        std::map <std::string, std::string> cache;
        std::set <int> uids;
        
    public:
        Client(std::shared_ptr <Channel> channel, std::string db_path1, std::string db_path2) : stub_(RPC::NewStub(channel)) {
            rocksdb::Options coptions;
            coptions.create_if_missing = true;
            coptions.merge_operator.reset(new rocksdb::StringAppendOperator());
            coptions.use_fsync = true;
            rocksdb::Status status1 = rocksdb::DB::Open(coptions, db_path1, &client_db);
            rocksdb::Status status2 = rocksdb::DB::Open(coptions, db_path2, &client_cache);
        }

        ~Client() {
            std::map<std::string, int>::iterator it1;
            for (it1 = d_cnt.begin(); it1 != d_cnt.end(); ++it1) {
                store(it1->first, std::to_string(it1->second), 0);
            }

            std::map<std::string, std::string>::iterator it2;
            for (it2 = cache.begin(); it2 != cache.end(); ++it2) {
                store(it2->first, it2->second, 1);
            }
            client_db->Flush(rocksdb::FlushOptions());
            client_cache->Flush(rocksdb::FlushOptions());
            delete client_db;
            delete client_cache;

            std::cout << "Bye~ " << std::endl;
        }

         int store(const std::string k, const std::string v, int f) {
            rocksdb::Status s;
            if (f == 0){
                s = client_db->Delete(rocksdb::WriteOptions(), k);
                s = client_db->Put(rocksdb::WriteOptions(), k, v);
            } else {
                s = client_cache->Delete(rocksdb::WriteOptions(), k);
                s = client_cache->Put(rocksdb::WriteOptions(), k, v);
            }
             if (s.ok()) return 0;
            else return -1;
        }



        std::string get(const std::string k, int f) {
            std::string tmp;
            rocksdb::Status s;
            if (f==0){
                s = client_db->Get(rocksdb::ReadOptions(), k, &tmp);
            } else {
                s = client_cache->Get(rocksdb::ReadOptions(), k, &tmp);
            }
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

         std::string write_cache(std::string k, std::string v) {
            {
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                cache[k] = v;
            }
            return "OK";
        }

        std::string delete_cache(std::string k) {
            {
                std::mutex m;
                std::lock_guard <std::mutex> lockGuard(m);
                cache.erase(k);
            }
            return "OK";
        }


        void read_cnt(std::string w, int& c) {
            std::map<std::string, int>::iterator it;
            it = d_cnt.find(w);
            c = -1;
            if (it != d_cnt.end()) {
                c = it->second; // TODO need to lock when read, but for our scheme, no need
            } else {
                std::string s = get(w, 0);
                if (s!=""){
                    char* cs = const_cast<char*>(s.c_str());
                    c = atoi(cs);
                    write_cnt(w, c);
                }
            }
        }

        void read_cache(std::string k, std::string& v) {
            std::map<std::string, std::string>::iterator it;
            it = cache.find(k);
            v= "";
            if (it != cache.end()) {
                v = it->second; // TODO need to lock when read, but for our scheme, no need
            } else {
                std::string s = get(k, 1);
                if (s!=""){
                    v = s;
                    write_cache(k, v);
                }
            }
        }


        std::string setup(std::string file, int maxd, int maxw){
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
            std::string keyword, ind, indc, ut, stag, sc, ss2, wc, e, label, v, enc, sxtag, scf, enc1, enc2;
            std::string last = "";
            int c = 0;
            int i;
            int tmp1 =0;
            std::string tmps, kid;
            AES_KEY key, key1, key2, key3, key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s%d", s2, &id);
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                keyword  = s2;
                std::cout<<keyword<<" "<<ind<<std::endl;
                indc = ind+"1";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                indc = ind+"2";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                indc = ind+"3";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                v = label + "1";
               	enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                v = label + "0";
                enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                enc = Cutil::Xor(enc1, enc2);
                request.set_index(1);
                request.set_label(label);
                request.set_enc(enc);
		        writer->Write(request);
                if(last ==""){
                    c =1;
                    tmp1 = 1;
                    stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                    while(id>tmp1){
                        tmps = std::to_string(100000000 + tmp1);
                        tmps = tmps.substr(1, 8);
                        indc = tmps+"1";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                        indc = tmps+"2";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                        indc = tmps+"3";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                        label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                        v = label + "0";
               	        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        request.set_index(1);
                        request.set_label(label);
                        request.set_enc(enc);
		                writer->Write(request);
			            tmp1++;
                    }

                    tmp1 = id +1;
                } else if (last != "" && last != keyword){
                    write_cnt(last, c);
                    c = 1;
                    stag = Cutil::F_aesni(&key4, keyword.c_str(), keyword.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
                    while(maxd>=tmp1){
                        tmps = std::to_string(100000000 + tmp1);
                        tmps = tmps.substr(1, 8);
                        indc = tmps+"1";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                        indc = tmps+"2";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                        indc = tmps+"3";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                        label = Cutil::F_aesni(&key1, last.c_str(), last.length(), 1);
                        v = label + "0";
               	        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        request.set_index(1);
                        request.set_label(label);
                        request.set_enc(enc);
		                writer->Write(request);
			            tmp1++;
                    }
                    tmp1 = 1;
                    while(id>tmp1){
                        tmps = std::to_string(100000000 + tmp1);
                        tmps = tmps.substr(1, 8);
                        indc = tmps+"1";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                        indc = tmps+"2";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                        indc = tmps+"3";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                        label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                        v = label + "0";
               	        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        request.set_index(1);
                        request.set_label(label);
                        request.set_enc(enc);
		                writer->Write(request);
			            tmp1++;
                    }
                    tmp1 = id +1;
                } else {
                    while(id>tmp1){
                        tmps = std::to_string(100000000 + tmp1);
                        tmps = tmps.substr(1, 8);
                        indc = tmps+"1";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                        indc = tmps+"2";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                        indc = tmps+"3";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                        //sxtag = keyword + tmps;
                        label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                        v = label + "0";
               	        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        request.set_index(1);
                        request.set_label(label);
                        request.set_enc(enc);
		                writer->Write(request);
			            tmp1++;
                    }
                    tmp1 ++;
                    c++;
                }
                last = keyword;
                sc = std::to_string(10000+c);
                scf = sc+ "0";
                ut = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1); 
                scf = sc+"1";
                ss2 = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                e =  Cutil::Xor("1"+ind, ss2);
                request.set_index(0);
                request.set_label(ut);
                request.set_enc(e);
		        writer->Write(request);
            }
            write_cnt(last, c);
            tmp1 = id +1;
            while(maxd>=tmp1){
                tmps = std::to_string(100000000 + tmp1);
                tmps = tmps.substr(1, 8);
                indc = tmps+"1";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                indc = tmps+"2";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                indc = tmps+"3";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                //sxtag = last + tmps;
                label = Cutil::F_aesni(&key1, last.c_str(), last.length(), 1);
                v = label + "0";
               	enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                enc = Cutil::Xor(enc1, enc2);
                request.set_index(1);
                request.set_label(label);
                request.set_enc(enc);
		        writer->Write(request);
		        tmp1++;
            }
            fclose(fp);
            for (int i=1; i<=maxd; i++){
                write_cache(std::to_string(i), "0");
            }
            write_cache("cachesiz", "0"); 
            write_cache("wnum", std::to_string(maxw));
            write_cache("dnum", std::to_string(maxd));
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




        std::string addkeywords(std::vector<std::string> newkeywords, int maxd){ //max the number of documents
            SetupRequestMessage request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<SetupRequestMessage>> writer(stub_->setup(&context, &exec_status));
            std::string keyword, ind, indc, kid, ut, stag, sc, ss1, ss2, wc, e, label, v, enc, sxtag, scf, enc1, enc2;
            std::string last = "";
            int c = 0;
            int tmp1 =0;
            std::string tmps;
            AES_KEY key, key1, key2, key3;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key);



            for (int i=1; i<=maxd; i++){
                ind = std::to_string(100000000 + i);
                ind = ind.substr(1, 8);
                indc = ind+"1";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                indc = ind+"2";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                indc = ind+"3";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                
                for (int j=0; j<newkeywords.size(); j++){
                    keyword = newkeywords.at(j);
                    label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                    v = label + "0";
               	    enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                    enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                    enc = Cutil::Xor(enc1, enc2);
                    request.set_index(1);
                    request.set_label(label);
                    request.set_enc(enc);
                    writer->Write(request);

                } 
            }

            for (int j=0; j<newkeywords.size(); j++){
                store(newkeywords.at(j), "0", 0);
            } 
            writer->WritesDone();
            Status status = writer->Finish();
            if (status.ok()) {
                std::string log = "add keywords completed";
                std::cout << log <<std::endl;
                return "OK";
            } else {
                return "FALSE";
            }
        }













        int consearch(std::vector<std::string> keywords, std::unordered_set<std::string>& sresult){
            //double start, end, time;
            //start = HDXTSU::Cutil::getCurrentTime();
            std::string sterm = keywords.at(0);
            std::vector<std::string> tresult, tresult2;

            int c1;
            std::string scf, st;
            SearchRequestMessage request;
            ClientContext context;
            SearchReply reply;
            std::unique_ptr <ClientReaderWriter<SearchRequestMessage, SearchReply>> stream(stub_->consearch(&context));
            AES_KEY key, key1, key2, key3, key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            std::string stag = Cutil::F_aesni(&key4, sterm.c_str(), sterm.length(), 1);
            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key5);
            read_cnt(sterm, c1);
            //std::cout<<"c1: "<<c1<<std::endl;
            if (c1 == -1){
                std::cout<< "the keyword " <<sterm<<" does not exist"<<std::endl;
                return 0;
            }
            request.set_index(c1);
            //end = HDXTSU::Cutil::getCurrentTime();
            //time = end-start;
            stream->Write(request);

           std::mutex writer_lock; 
            auto send_st = [this, &stream, &writer_lock, &request](const int index, const std::string st) {
                request.set_index(index);
                request.set_st(st);
                writer_lock.lock();
                stream->Write(request);
                writer_lock.unlock();
            };

            ThreadPool send_st_pool(1);
            std::mutex out_lock; 
            auto st_generation = [this, &key5, &send_st, &send_st_pool, &out_lock](
                       const uint8_t index, const size_t max, const uint8_t N) {

                    
                std::string st, scf;
                if (index < max) {
                    scf = std::to_string(10000+index+1) + "0";
                    st = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                    send_st_pool.enqueue(send_st, index+1, st);
                }

                for (size_t i = index + N; i < max; i += N) {
                    scf = std::to_string(10000+i+1) + "0";
                    st = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                    send_st_pool.enqueue(send_st, i+1, st);
                }
            };

            //start = HDXTSU::Cutil::getCurrentTime();
            std::vector<std::thread> send_st_threads;

            unsigned n_threads = std::thread::hardware_concurrency();
            for (uint8_t t = 0; t < n_threads; t++) {
                send_st_threads.emplace_back(st_generation, t, c1, n_threads);
            }
     
            std::vector<std::string> upds(c1);
            auto process_upd = [this, &key5, &sterm, &upds, &writer_lock](
                       const int index, const std::string e) {
                
                std::string sc = std::to_string(10000+index);
                std::string scf = sc+ "1";
                std::string ss2 = Cutil::F_aesni(&key5, scf.c_str(), scf.length(), 1);
                std::string ss1 =  Cutil::Xor(e, ss2);
                upds[index-1] = ss1; 
                
            };

            ThreadPool process_upd_pool(8); 

            int index;
            std::string e;
            int e_cnt = 0;

            //end = HDXTSU::Cutil::getCurrentTime();
            //time += (end - start);
            while (stream->Read(&reply)){
                //start = HDXTSU::Cutil::getCurrentTime();
                index = reply.index();
                e = reply.eid();
                e_cnt++;
                process_upd_pool.enqueue(process_upd, index, e);
                if (e_cnt == c1){
                    break;
                }
                //end = HDXTSU::Cutil::getCurrentTime();
                //time += (end - start);
            }


           //start = HDXTSU::Cutil::getCurrentTime();
           for (uint8_t t = 0; t < n_threads; t++) {
                send_st_threads[t].join();
            }
            //end = HDXTSU::Cutil::getCurrentTime();
            //time += (end - start);

            send_st_pool.join();

            //start = HDXTSU::Cutil::getCurrentTime();
            process_upd_pool.join();

            std::string ss1, op, ind; 
            int i;
            for (i=0; i<upds.size(); i++){
                ss1 = upds.at(i);
                op = ss1.substr(0, 1);
                ind = ss1.substr(1, 8);
                if (op == "1"){
                    tresult.push_back(ind);
                } else if (op == "0"){
                    std::vector<std::string>::iterator it;
                    it = find(tresult.begin(), tresult.end(), ind);
                    if (it != tresult.end()){
                        tresult.erase(it);
                    }
                }
            }

            auto send_xrequest = [&stream, &request, &writer_lock](int index, std::string label, std::string d1, std::string d2) {
                 request.set_index(index);
                request.set_label(label);
                request.set_d1(d1);
                request.set_d2(d2);
                writer_lock.lock();
                stream->Write(request);
                writer_lock.unlock();

            };
            ThreadPool send_xrequest_pool(1);
            int c = tresult.size();
            std::mutex    vec_mutex;
            std::vector<int> flags(c, 1);
            std::vector<std::string> sums(c, "0000000000000000");
            std::vector<int> nums(c, 0);
            int n = keywords.size()-1;
            auto process_xquery = [this, &key, &n, &flags, &out_lock, &send_xrequest, &send_xrequest_pool, &vec_mutex, &sums, &nums](
                       const int index, const std::string keyword, const std::string  ind, const int cnt) {
                std::string wid, label, b, v, sum, enc, enc1, enc2, indc, kid;
                int num, flag;
                AES_KEY key1, key2, key3; 
                indc = ind + "1";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                indc = ind+"2";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                indc = ind+"3";
                kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		        Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                send_xrequest_pool.enqueue(send_xrequest, index, label, "", "");
                if (flags.at(index)==0){
                    flag =0;
                    vec_mutex.lock();
                    num = nums.at(index);
                    num ++;
                    nums.at(index) = num;
                    vec_mutex.unlock();
                } else {
                    read_cache(label,b);
                    if (b=="0"){
                        flag =0;
                        vec_mutex.lock();
                        flags.at(index) = 0;
                        num = nums.at(index);
                        num ++;
                        nums.at(index) = num;
                        vec_mutex.unlock();
                    } else if (b == "1") {
                        flag =1;
                        v = label + "0";
                        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        v = label + std::to_string(cnt);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        vec_mutex.lock();
                        num = nums.at(index);
                        sum = sums.at(index);
                        sum = Cutil::Xor(sum, enc);
                        sums.at(index) =sum;
                        num ++;
                        nums.at(index) = num;
                        vec_mutex.unlock();
                    } else if (b == ""){
                        flag =1;
                        v = label + "1";
                        enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                        v = label + std::to_string(cnt);
                        enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                        enc = Cutil::Xor(enc1, enc2);
                        vec_mutex.lock();
                        num = nums.at(index);
                        sum = sums.at(index);
                        sum = Cutil::Xor(sum, enc);
                        sums.at(index) =sum;
                        num ++;
                        nums.at(index) = num;
                        vec_mutex.unlock();
                    }
                }
                if (flag ==0 && num ==n){
                    AutoSeededRandomPool rnd;
                    byte rand[16];
                    std::string d1, d2;
                    rnd.GenerateBlock(rand, 16);
                    d1 = std::string((const char*)rand, 16);
                    rnd.GenerateBlock(rand, 16);
                    d2 = std::string((const char*)rand, 16);
                    send_xrequest_pool.enqueue(send_xrequest, index, "", d1, d2);
                }else if (flag ==1 && num ==n){
                    AutoSeededRandomPool rnd;
                    byte rand[16];
                    std::string d1, d2;
                    rnd.GenerateBlock(rand, 16);
                    std::string r = std::string((const char*)rand, 16);
                    d1 = Cutil::Xor(r, sums.at(index));
                    std::string s = "0000000000000000"; 
                    d2 = Cutil::CTR_AESEncryptStr((byte * )(r.c_str()), iv_s, s);
                    send_xrequest_pool.enqueue(send_xrequest, index, "", d1, d2);

                }
                     

            };
            ThreadPool process_xquery_pool(8); 
            request.set_n(tresult.size());
            //end = HDXTSU::Cutil::getCurrentTime();
            //time += (end-start);
            stream->Write(request);
            //start = HDXTSU::Cutil::getCurrentTime(); 
            std::string keyword, tmpind, scnt;
            char *cs;
            int id, cnt;
            for(int i=0; i<tresult.size(); i++){
                ind = tresult.at(i);
                tmpind = "1"+ind;
                cs = const_cast<char*>(tmpind.c_str());
                id = atoi(cs) - 100000000;
                read_cache(std::to_string(id), scnt);
                cs = const_cast<char*>(scnt.c_str());
                cnt = atoi(cs);
                for (int j=1; j<keywords.size(); j++){
                    keyword = keywords.at(j);
                    process_xquery_pool.enqueue(process_xquery, i, keyword, ind, cnt);
                }
            }

          
            process_xquery_pool.join();
            //end = HDXTSU::Cutil::getCurrentTime();
            //time += (end-start);
            send_xrequest_pool.join();
            
            stream->WritesDone();
             while(stream->Read(&reply)){
                //start = HDXTSU::Cutil::getCurrentTime(); 
                index = reply.index();
                ind = tresult.at(index);
                sresult.insert(ind);
                //end = HDXTSU::Cutil::getCurrentTime();
                //time += (end-start); 
             
            }

            /*std::ofstream ofile;
            ofile.open("susearchtimeclient3.txt", std::ios::app);
            ofile << time*1000 << std::endl;*/

            Status status = stream->Finish();
            if (!status.ok()) {
                std::cout << status.error_details()<< std::endl;
            }

            return tresult.size();

        }



        std::string updatetrace(std::vector<std::pair<std::string, int>> updates){
            AES_KEY key, key1, key4, key5;
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key4);
            
            UpdateRequestMessage1 request;
            ClientContext context;
            ExecuteStatus exec_status;
            std::unique_ptr <ClientWriterInterface<UpdateRequestMessage1>> writer(stub_->tupdate(&context, &exec_status));

            int id, c;
            std::string opkeyword, keyword, op, ind, stag, sc, scf, ss2, sxtag, label, ut, e, indc, kid;
            std::string swnum;
            read_cache("wnum", swnum);
            char* cs = const_cast<char*>(swnum.c_str());
            int wnum = atoi(cs);
            std::string ssiz;
            read_cache("cachesiz", ssiz);
            cs = const_cast<char*>(ssiz.c_str());
            int siz = atoi(cs);
            std::pair<std::string, int> p;
            for(int i=0; i<updates.size(); i++){
                 p = updates.at(i);
                 opkeyword = p.first;
                 op = opkeyword.substr(0, 1);
                 keyword = opkeyword.substr(1);
                 id = p.second;
                 ind = std::to_string(100000000 + id);
                 ind = ind.substr(1, 8);
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
                if (siz+1 <= wnum){
                    indc = ind+"1";
                    kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                    label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                    write_cache(label, op);
                    uids.insert(id);
                    siz ++;
                } else {
                    indc = ind+"1";
                    kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		            Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                    label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                    write_cache(label, op);
                    uids.insert(id);
                    EvictRequestMessage request2;
                    ClientContext context2;
                    ExecuteStatus exec_status2;
                    std::unique_ptr <ClientWriterInterface<EvictRequestMessage>> writer2(stub_->evict(&context2, &exec_status2));
                    rocksdb::Iterator *it = client_db->NewIterator(rocksdb::ReadOptions());
                    std::string skey, sid, u, v, enc1, enc2, enc3;
                    std::string value;
                    rocksdb::Status s;
                    std::vector<std::string> keywords;
                    for (it->SeekToFirst(); it->Valid(); it->Next()) {
                         skey = it->key().ToString();
                         keywords.push_back(skey);
                    }
                    AES_KEY key2, key3;
                    std::string scnt;
                    int cnt;
                    request2.set_index("1");
                    int stat =0;
                    for (auto sit =uids.begin(); sit!=uids.end(); sit++){
                        id = *sit;
                        read_cache(std::to_string(id), scnt);
                        cs = const_cast<char*>(scnt.c_str());
                        int cnt = atoi(cs);
                        sid = std::to_string(100000000 + id);
                        sid = sid.substr(1, 8);
                        indc = sid+"1";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key1);
                        indc = sid+"2";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key2);
                        indc = sid+"3";
                        kid = Cutil::F_aesni(&key, indc.c_str(), indc.length(), 1);
		                Cutil::AES_set_encrypt_key((unsigned char *)kid.c_str(), 128, &key3);
                        for (int i=0; i<keywords.size(); i++){
                            keyword = keywords.at(i);
                            label = Cutil::F_aesni(&key1, keyword.c_str(), keyword.length(), 1);
                            read_cache(label, value);
                            if (value == ""){
                                v = label + std::to_string(cnt);
               	                enc1 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                                v = label + std::to_string(cnt+1);
                                enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                                u= Cutil::Xor(enc1, enc2);
                            }else {
                                v = label + "1";
                                enc1 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                                v = label + "0";
                                enc2 = Cutil::F_aesni(&key2, v.c_str(), v.length(), 1);
                                enc3= Cutil::Xor(enc1, enc2);
                                v = label + std::to_string(cnt);
               	                enc1 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                                v = label + std::to_string(cnt+1);
                                enc2 = Cutil::F_aesni(&key3, v.c_str(), v.length(), 1);
                                u= Cutil::Xor(enc1, enc2);
                                u= Cutil::Xor(u, enc3);
                                delete_cache(label);
                            }
                            request2.set_label(label);
                            request2.set_enc(u);
                            writer2->Write(request2);
                            stat++;
                        }

                        write_cache(std::to_string(id), std::to_string(cnt+1));
                    }
                    std::cout<<stat<<std::endl;
                    request2.set_index("2");
                    writer2->Write(request2);
                    uids.clear();
                    siz =0;
                    writer2->WritesDone();
                    Status status = writer2->Finish();
                    if (status.ok()) {
                        std::string log = "DB Evict completed";
                        std::cout << log <<std::endl;
                    } else {
                        return "FALSE";
                    }

                }

            } 

            write_cache("cachesiz", std::to_string(siz));
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

    };


    

} // namespace HDXTSU

#endif // HDXTSU_CLIENT_H
