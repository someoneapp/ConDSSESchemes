#ifndef HXT_SERVER_H
#define HXT_SERVER_H
#include <grpc++/grpc++.h>
#include "HXT.grpc.pb.h"
#include "crypto.util.h"
#include "thread_pool.hpp"
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include<iostream>
#include<fstream>
#include<iomanip>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::Status;
using grpc::ServerReaderWriter;

CryptoPP::byte iv_s[17] = "0123456789abcdef";

namespace HXT {
    class HXTServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *server_db1;
        static rocksdb::DB *server_db2;
        std::size_t m;
        int dnum;

    public:
        HXTServiceImpl(const std::string db_path1, const std::string db_path2) {
            signal(SIGINT, abort);
            rocksdb::Options options;
            options.create_if_missing = true;
	        options.max_background_compactions = 4;
            options.max_subcompactions = 2;
            options.compaction_style=rocksdb::kCompactionStyleLevel;
            options.level_compaction_dynamic_level_bytes=true;
            options.compression_per_level = {rocksdb::kNoCompression, rocksdb::kNoCompression, rocksdb::kNoCompression, rocksdb::kLZ4Compression, rocksdb::kLZ4Compression, rocksdb::kLZ4Compression};
            options.compression=rocksdb::kLZ4Compression;
            options.compression_opts.level=4;
            options.bottommost_compression=rocksdb::kZSTD;
            options.bottommost_compression_opts.max_dict_bytes = 1 << 14;
            options.bottommost_compression_opts.zstd_max_train_bytes=1 << 18;
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
            std::string str;
            bool b = get(server_db2, "m", str);
            m = strtoul(str.c_str(), NULL, 10);
            b = get(server_db2, "dnum", str);
            dnum = strtoul(str.c_str(), NULL, 10);
        }


        static void abort(int signum) {
            exit(signum);
        }

        static int store(rocksdb::DB *&db, const std::string ut, const std::string e) {
            rocksdb::Status s;
            rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
            {
                s = db->Put(write_option, ut, e);
            }
	    if (!s.ok()){
                std::cout << s.ToString() << std::endl;
            }

            assert(s.ok());
            if (s.ok()) return 0;
            else {
                return -1;
            }
        }

        static bool get(rocksdb::DB *&db, const std::string st, std::string &e) {
            rocksdb::Status s;
            {
                s = db->Get(rocksdb::ReadOptions(), st, &e);
            }
            return s.ok();
        }

        static int delete_entry(rocksdb::DB *&db, const std::string label) {
            int status = -1;
            try {
                rocksdb::WriteOptions write_option = rocksdb::WriteOptions();
                rocksdb::Status s;
                s = db->Delete(write_option, label);
                if (s.ok()) status = 0;
            } catch (std::exception &e) {
                std::cerr << "in delete_entry() " << e.what() << std::endl;
                exit(1);
            }
            return status;
        }


       


         Status setup(ServerContext *context, ServerReader <SetupRequestMessage> *reader, ExecuteStatus *response) {
            std::cout<<"setup request received"<<std::endl;
            SetupRequestMessage request;
            int index;
            std::string s1, s2, s3;
            //int cnt = 0;
            while (reader->Read(&request)) {
                index = request.index();
                s1 = request.label();
                s2 = request.enc();
                if (index == 0){
                    store(server_db1, s1, s2);
                } else if (index == 1){
                    //cnt++;
                    store(server_db2, s1, s2);
                    s3 =s1;
                } else {
                     m = strtoul(s3.c_str(), NULL, 10) + 1;
                     store(server_db2, "m", std::to_string(m));
                     dnum = strtoul(s1.c_str(), NULL, 10) + 1;
                     store(server_db2, "dnum", std::to_string(dnum));
                }
            }
            /*m = strtoul(s1.c_str(), NULL, 10) + 1;
            store(server_db2, "m", std::to_string(m));*/
            return Status::OK;
        }




        Status consearch(ServerContext *context, ServerReaderWriter< SearchReply, SearchRequestMessage>* stream) {
            std::cout<<"search request received"<<std::endl;
            //double start, end, time;
            //start = Cutil::getCurrentTime();
            typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> GroupParameters;
            typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element Element;
            GroupParameters group;
            group.Initialize(CryptoPP::ASN1::secp256r1());

            SearchRequestMessage request;
            SearchReply reply;
            //end = Cutil::getCurrentTime();
            //time = end - start;
            stream->Read(&request);
            //start = Cutil::getCurrentTime(); 
            std::string stag;
            stag = request.stag();
            AES_KEY key;
            Cutil::AES_set_encrypt_key((unsigned char *)stag.c_str(), 128, &key);
            std::atomic_uint tres_size(0);
            std::map<int, std::string> eids;
	        std::map<int, CryptoPP::Integer> ys;

            std::mutex    map_lock;
	        std::mutex    writer_lock;
            //end = Cutil::getCurrentTime();
            //tmp = end - start;
            //time += (end-start);

	        auto access_job1 = [this, &key, &eids, &ys, &map_lock, &tres_size](
                       const uint8_t index, const size_t max, const uint8_t N) {
                std::string sc, ut, ey, e, sy;
                bool b;
                if (index < max) {
                     sc = std::to_string(index+1);
                     ut =  Cutil::F_aesni(&key, sc.c_str(), sc.length(), 1);
                     bool b = get(server_db1, ut, ey);
                     if (b){
			            tres_size++;
			            e = ey.substr(0, 8);
                        sy = ey.substr(8);
                        CryptoPP::Integer y1(sy.c_str());
                        map_lock.lock();
                        eids[index] = e;
			            ys[index] = y1;
                        map_lock.unlock();
                    } else{
                        return;
                    }
                }

                for (size_t i = index + N; i < max; i += N) {
                    sc = std::to_string(i+1);
                    ut =  Cutil::F_aesni(&key, sc.c_str(), sc.length(), 1);
                    bool b = get(server_db1, ut, ey);
                    if (b){
                        tres_size++;
			            e = ey.substr(0, 8);
                        sy = ey.substr(8);
                        CryptoPP::Integer y1(sy.c_str());
                        map_lock.lock();
                        eids[i] = e;
			            ys[i] = y1;
                        map_lock.unlock();
                    } else{
                        return;
                    }
                }
            };


            //start = Cutil::getCurrentTime();
            std::vector<std::thread> access_threads;
            unsigned n_threads = std::thread::hardware_concurrency();
            for (uint8_t t = 0; t < n_threads; t++) {
                access_threads.emplace_back(access_job1, t, dnum, n_threads);
            }
            for (uint8_t t = 0; t < n_threads; t++) {
                access_threads[t].join();
            }
            //end = Cutil::getCurrentTime();
            //tmp = end-start;
            //time += (end-start);
            

             auto send_xreply = [&stream, &reply, &writer_lock](const int index, const std::string h) {
                reply.set_index(index);
                reply.set_h(h);
                writer_lock.lock();
                stream->Write(reply);
                writer_lock.unlock();

            };
            ThreadPool send_xreply_pool(1);

            std::mutex    vec_mutex1;
            std::vector<std::string> ssums(tres_size);
           ThreadPool subaccess_pool(8);
           auto subaccess_job = [this, &vec_mutex1, &ssums, &send_xreply, &send_xreply_pool](
                          int index, unsigned int salt, const std::string sxtag) {
                bool b;
                std::string enc, sum;
                unsigned int h = Cutil::hash_bf(reinterpret_cast<const unsigned char*>(sxtag.data()),sxtag.size(), salt);
                unsigned int h_bf = h%m;
                std::string s = std::to_string(h_bf);
                b = get(server_db2, s, enc);
                if (b == 0){
                    std::cout<<"does not find anything"<<std::endl;
                } else{ 
                    vec_mutex1.lock();
                    sum = ssums.at(index);
                    if (sum == ""){
                        ssums[index] = enc;
                    } else {
                        sum = Cutil::Xor(sum, enc);
                        ssums[index] = sum; 
                    }
                    vec_mutex1.unlock();
                }
                send_xreply_pool.enqueue(send_xreply, index, s);
            };

            

           std::vector<unsigned int> salt;
            Cutil::generate_salt(20, salt);
            std::mutex    vec_mutex2;
            ThreadPool access_pool(8);
            auto access_job = [this, &vec_mutex2, &salt, &group, &eids, &ys, &subaccess_pool, &subaccess_job](
                          int index, const std::string xtokenx, const std::string xtokeny) {
                CryptoPP::Integer y=ys.at(index);
                CryptoPP::Integer tx(xtokenx.c_str());
                CryptoPP::Integer ty(xtokeny.c_str());
                Element exy(tx, ty);
                Element xtag = group.ExponentiateElement(exy, y);
                std::string tmp1 = Cutil::Inttostring(xtag.x);
                std::string tmp2= Cutil::Inttostring(xtag.y);
                std::string sxtag = tmp1 + tmp2;
                for (int k =0; k<salt.size(); k++){
                    subaccess_pool.enqueue(subaccess_job, index, salt.at(k), sxtag);

                } 
            };

            std::string xtokenx, xtokeny;
            int index;
            while (stream->Read(&request)){
                //start = Cutil::getCurrentTime();
                index = request.index();
                xtokenx = request.xtokenx();
                if(xtokenx==""){
                    break;
                }
                xtokeny = request.xtokeny();
                access_pool.enqueue(access_job, index, xtokenx, xtokeny);
                //end = Cutil::getCurrentTime();
                //tmp = end - start;
                //time += (end-start);
            }
            //start = Cutil::getCurrentTime();
            access_pool.join();
            subaccess_pool.join();
            //end = Cutil::getCurrentTime();
            //tmp = end - start;
            //time += (end-start);
            send_xreply_pool.join();
            reply.set_h("");
            stream->Write(reply);     


            std::string sum, d1, d2, r;
            std::string s = "0000000000000000";
            while (stream->Read(&request)){
                //start = Cutil::getCurrentTime();
                index = request.index();
                d1 = request.d1();
                d2 = request.d2();
                r = Cutil::Xor(d1, ssums.at(index));
                std::string s1 = Cutil::CTR_AESDecryptStr((CryptoPP::byte *)(r.c_str()), iv_s, d2);
                //std::cout<<s1<<std::endl;
                if (s1 == s){
                    reply.set_index(index);
                    reply.set_eid(eids.at(index));
                    //end = Cutil::getCurrentTime();
                    //time += (end-start);
                    writer_lock.lock();
                    stream->Write(reply);
                    writer_lock.unlock();
                } else {
                    //end = Cutil::getCurrentTime();
                    //tmp = end - start;
                    //time += (end-start);
                }
            }
            return Status::OK;

        }


        


        


    };

}

rocksdb::DB *HXT::HXTServiceImpl::server_db1;
rocksdb::DB *HXT::HXTServiceImpl::server_db2;

void RunServer(std::string db_path1, std::string db_path2) {
    std::string server_address("0.0.0.0:50051");
    HXT::HXTServiceImpl service(db_path1, db_path2);
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout<<"Server listening on " << server_address << std::endl;
    server->Wait();
}

#endif
