#ifndef HXT_CLIENT_H
#define HXT_CLIENT_H

#include <grpc++/grpc++.h>
#include "HXT.grpc.pb.h"
#include "crypto.util.h"
#include "HXT.string_append_operator.h"
#include <thread>
#include "thread_pool.hpp"
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include<iostream>
#include<fstream>
#include<iomanip>
#include<stdio.h>
#include<sys/stat.h>

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

byte k_h1[17] = "qwertyuioplkjhgf";
byte iv_h1[17] = "qazxsdcvfgbnhjkl";

byte k_h2[17] = "9w7r5y0iog43jh2f";
byte iv_h2[17] = "2345678909876543";

byte k_i[17] = "sdfgregreghthrth";
byte k_z[17] = "gewgrgwrgwgerhgt";

byte k_x[17] = "8w8687ug90970909";

namespace HXT {

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
            rocksdb::Status status = rocksdb::DB::Open(coptions, db_path, &client_db);
        }

        ~Client() {
            std::map<std::string, int>::iterator it;
            for (it = d_cnt.begin(); it != d_cnt.end(); ++it) {
                store(it->first, std::to_string(it->second));
            }
            client_db->Flush(rocksdb::FlushOptions());
            delete client_db;

            std::cout << "Bye~ " << std::endl;
        }

         int store(const std::string k, const std::string v) {
            rocksdb::Status s = client_db->Delete(rocksdb::WriteOptions(), k);
            s = client_db->Put(rocksdb::WriteOptions(), k, v);
            if (s.ok()) return 0;
            else return -1;
        }

        std::string get(const std::string k) {
            std::string tmp;
            rocksdb::Status s = client_db->Get(rocksdb::ReadOptions(), k, &tmp);
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


        std::string setup(std::string file, std::size_t  N, int maxd){
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
            std::string keyword, ind;
            std::string last = "";
            int c = 0;
            int i;
            std::string e, sy, stag, label, sxtag, tmp1, tmp2, sc, pos, wc, ss2;

            typedef DL_GroupParameters_EC<ECP> GroupParameters;
            typedef DL_GroupParameters_EC<ECP>::Element Element;
            GroupParameters group;
            group.Initialize(ASN1::secp256r1());
            Integer p = group.GetSubgroupOrder();

            Integer xid, z, y, w_p;
            Element xtag;
            unsigned int h, h_bf;
            
            std::size_t m = 29*N;
	        std::cout<<m<<std::endl;

            std::vector<int> bf(m);
	        std::cout<<bf.max_size()<<std::endl;
	        std::cout<<bf.capacity()<<std::endl;
	        std::cout<<bf.size()<<std::endl;
            std::vector<unsigned int> salt;
            Cutil::generate_salt(20, salt);
            std::cout<<"salt: "<<salt.size()<<std::endl;

            AES_KEY key1, key2, key3, key4, key5, key6, key7;
            Cutil::AES_set_encrypt_key((unsigned char *)k_i, 128, &key1);
            Cutil::AES_set_encrypt_key((unsigned char *)k_z, 128, &key2);
            Cutil::AES_set_encrypt_key((unsigned char *)k_x, 128, &key3);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key4);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key5);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key7);
            ALIGN(16) const char* keye;
            ALIGN(16) const char* pid;
            ALIGN(16) char eid[8];
            
            while (fgets(s1, 100, fp)){
                sscanf(s1, "%s%d", s2, &id);
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                keyword  = s2;
		        std::cout<<keyword<<" "<<ind<<std::endl;
                if(last ==""){
                    c =1;
                    stag = Cutil::F_aesni(&key5, keyword.c_str(), keyword.length(), 1);
                    Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key6);
                    Cutil::F_p(keyword, &key3, p, w_p);
                } else if (last != "" && last != keyword){
                    write_cnt(last, c);
                    c = 1;
                    stag = Cutil::F_aesni(&key5, keyword.c_str(), keyword.length(), 1);
                    Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key6);
                    Cutil::F_p(keyword, &key3, p, w_p);
                } else {
                    c++;
                }
                last = keyword;
                Cutil::F_p(ind, &key1, p, xid);
                Cutil::F_p(keyword+std::to_string(c), &key2, p, z);
                y = a_times_b_mod_c(xid,z.InverseMod(p),p);
                sy = Cutil::Inttostring(y);
                sc = std::to_string(c);
                label = Cutil::F_aesni(&key6, sc.c_str(), sc.length(), 1);
                wc = keyword + sc;
                ss2 = Cutil::F_aesni(&key4, wc.c_str(), wc.length(), 1);
                e =  Cutil::Xor(ind, ss2);
                
                request.set_index(0);
                request.set_label(label);
                request.set_enc(e+sy);
                writer->Write(request);
                  

                xtag = group.ExponentiateBase(a_times_b_mod_c(w_p,xid,p));
                tmp1 = Cutil::Inttostring(xtag.x);
                tmp2= Cutil::Inttostring(xtag.y);
                sxtag = tmp1 + tmp2;

                for (i =0; i<salt.size(); i++){
                    h = Cutil::hash_bf(reinterpret_cast<const unsigned char*>(sxtag.data()),sxtag.size(), salt.at(i));
                    h_bf = h%m;
                    bf.at(h_bf) = 1;
                }
            }
            write_cnt(last, c);
            fclose(fp);
            std::string enc;
            request.set_index(1);
            for (i=0; i<m; i++){
                pos = std::to_string(bf.at(i)) + std::to_string(i);
                enc = Cutil::F_aesni(&key7, pos.c_str(), pos.length(), 1);
                request.set_label(std::to_string(i));
                request.set_enc(enc);
                writer->Write(request);
            }
            request.set_index(2);
            request.set_label(std::to_string(maxd));
            writer->Write(request);
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
            SearchRequestMessage request;
            ClientContext context;
            SearchReply reply;
            std::unique_ptr <ClientReaderWriter<SearchRequestMessage, SearchReply>> stream(stub_->consearch(&context));

            AES_KEY key1, key2, key3, key4, key5, key6, key7;
            Cutil::AES_set_encrypt_key((unsigned char *)k_z, 128, &key2);
            Cutil::AES_set_encrypt_key((unsigned char *)k_x, 128, &key3);
            Cutil::AES_set_encrypt_key((unsigned char *)k_s, 128, &key4);
            Cutil::AES_set_encrypt_key((unsigned char *)k_t, 128, &key5);
            Cutil::AES_set_encrypt_key((unsigned char *)k_h1, 128, &key7);

            std::string sterm = keywords.at(0);
            int c;
            std::string stag = Cutil::F_aesni(&key5, sterm.c_str(), sterm.length(), 1);
            request.set_stag(stag);
            int n = keywords.size() -1;
	        //end = Cutil::getCurrentTime();
	        //time = end - start;
            stream->Write(request);
	        //start = Cutil::getCurrentTime();
            read_cnt(sterm, c); 
            typedef DL_GroupParameters_EC<ECP> GroupParameters;
            typedef DL_GroupParameters_EC<ECP>::Element Element;
            GroupParameters group;
            group.Initialize(ASN1::secp256r1());
            Integer p = group.GetSubgroupOrder();
            int k;
            std::string eid, h;
	        std::mutex writer_lock;
	        //end = Cutil::getCurrentTime();
            //tmp = end - start;
            //time += (end-start);
	        


             auto send_xrequest = [&stream, &writer_lock, &request](const int i, const int j, std::string x, std::string y) {
                request.set_index(i);
                request.set_xtokenx(x);
                request.set_xtokeny(y);
                writer_lock.lock();
                stream->Write(request);
                writer_lock.unlock();

            };
            ThreadPool send_xrequest_pool(1);

        
            auto compute_xtoken = [&sterm, &key2, &key3, &send_xrequest, &send_xrequest_pool](const int i, const int j, const std::string s) {
                Integer z, w_p;
                Element xtoken;
                std::string xtokenx, xtokeny;
		        GroupParameters group;
                group.Initialize(ASN1::secp256r1());
                Integer p = group.GetSubgroupOrder();
                Cutil::F_p(sterm+std::to_string(i+1), &key2, p, z);
                Cutil::F_p(s, &key3, p, w_p);
                xtoken = group.ExponentiateBase(a_times_b_mod_c(z,w_p,p));
                xtokenx = Cutil::Inttostring(xtoken.x);
                xtokeny= Cutil::Inttostring(xtoken.y);
                send_xrequest_pool.enqueue(send_xrequest, i, j, xtokenx, xtokeny);
            };
            ThreadPool compute_xtoken_pool(8);

	        //start = Cutil::getCurrentTime();
            std::string keyword;
            for (int i=0; i<c; i++){
                for (int j =1; j<=n; j++){
                    keyword = keywords.at(j);
                    compute_xtoken_pool.enqueue(compute_xtoken, i, j, keyword);
                }
            }

            compute_xtoken_pool.join();
	        //end = Cutil::getCurrentTime();
	        //tmp = end - start;
	        //time += (end-start);
	        send_xrequest_pool.join();
		
            request.set_xtokenx("");
            stream->Write(request);

            
            auto send_xrequest2 = [&stream, &writer_lock, &request](const int i, const std::string d1, const std::string d2) {
                request.set_index(i);
                request.set_d1(d1);
                request.set_d2(d2);
                writer_lock.lock();
                stream->Write(request);
                writer_lock.unlock();

            };
            ThreadPool send_xrequest2_pool(1);
            
            std::mutex    vec_mutex;
            std::vector<std::string> sums(c);
            std::vector<int> cnts(c);
            
            auto compute_xtoken2 = [&vec_mutex, &key7, &sums, &n, &send_xrequest2_pool, &send_xrequest2, &cnts](int index, const std::string h) {
                std::string sum;
                std::string pos = std::to_string(1) + h;
                std::string enc = Cutil::F_aesni(&key7, pos.c_str(), pos.length(), 1);
                vec_mutex.lock();
                sum = sums.at(index);
                if (sum == ""){
                    cnts[index] = 1;
                    sums[index] = enc;
                } else {
                    sum = Cutil::Xor(sum, enc);
                    sums[index] = sum;
                    cnts[index] ++;
                    if (cnts[index] == 20*n){
                        AutoSeededRandomPool rnd;
                        byte rand[16];
                        std::string d1, d2;
                        rnd.GenerateBlock(rand, 16);
                        std::string r = std::string((const char*)rand, 16);
                        d1 = Cutil::Xor(r, sums.at(index));
                        std::string s = "0000000000000000"; 
                        d2 = Cutil::CTR_AESEncryptStr((byte * )(r.c_str()), iv_s, s);
                        send_xrequest2_pool.enqueue(send_xrequest2, index, d1, d2);
                    } 
                }
                vec_mutex.unlock();


            };

            ThreadPool compute_xtoken2_pool(8);
            
            int index;
            while (stream->Read(&reply)){
		            //start = Cutil::getCurrentTime();
                    h = reply.h();
                    if(h==""){
                        break;
                    }
                    index = reply.index();
                    compute_xtoken2_pool.enqueue(compute_xtoken2, index, h);
		             //end = Cutil::getCurrentTime();
		             //tmp = end - start;
		            //time += (end-start); 

            }
	        //start = Cutil::getCurrentTime();
            compute_xtoken2_pool.join();
            //end = Cutil::getCurrentTime();
	        //tmp = end - start;
	        //time += (end-start);
            send_xrequest2_pool.join();

            stream->WritesDone();
	    
            std::string wc, ss2, ind;
            while(stream->Read(&reply)){
		        //start = Cutil::getCurrentTime();
                index = reply.index();
                eid = reply.eid();
                //ofile<<index<<eid;
                wc = sterm + std::to_string(index+1);
                ss2 = Cutil::F_aesni(&key4, wc.c_str(), wc.length(), 1);
                ind =  Cutil::Xor(eid, ss2);
                sresult.insert(ind);
		        //end = Cutil::getCurrentTime();
		        //tmp = end - start;
		        //time += (end-start);
            }

            /*std::ofstream ofile;
            ofile.open("hxtsearchtimeclient1.txt", std::ios::app);
            ofile <<c<<" "<< time*1000 << std::endl;*/

            Status status = stream->Finish();
            if (!status.ok()) {
                std::cout << status.error_details()<< std::endl;
            }
	        return c;
        }



        
        

        

    };

}

#endif