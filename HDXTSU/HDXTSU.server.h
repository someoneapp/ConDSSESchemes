#ifndef HDXTSU_SERVER_H
#define HDXTSU_SERVER_H
#include <grpc++/grpc++.h>
#include "HDXTSU.grpc.pb.h"
#include "crypto.util.h"
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include "thread_pool.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::Status;
using grpc::ServerReaderWriter;

CryptoPP::byte iv_s[17] = "0123456789abcdef";

namespace HDXTSU {
    class HDXTSUServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *server_db1;
        static rocksdb::DB *server_db2;
        int num_tmp;

    public:
        HDXTSUServiceImpl(const std::string db_path1, const std::string db_path2) {
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
            options.bottommost_compression_opts.level=10;
            options.bottommost_compression_opts.enabled=true;

            rocksdb::BlockBasedTableOptions table_options;
            table_options.block_size=16*1024;
            table_options.format_version = 4;
            table_options.index_block_restart_interval = 16;
            table_options.enable_index_compression=false;
            options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
            num_tmp=0;
            rocksdb::Status s1 = rocksdb::DB::Open(options, db_path1, &server_db1);
            if (!s1.ok()) {
                std::cerr << "open ssdb1 error:" << s1.ToString() << std::endl;
            }
            rocksdb::Status s2 = rocksdb::DB::Open(options, db_path2, &server_db2);
            if (!s2.ok()) {
                std::cerr << "open ssdb2 error:" << s2.ToString() << std::endl;
            }
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
            assert(s.ok());
            if (s.ok()) return 0;
            else {
                std::cerr << s.ToString() << std::endl;
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

        static int open_DB(rocksdb::DB *&db, const std::string file) {
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
            options.bottommost_compression_opts.level=10;
            options.bottommost_compression_opts.enabled=true;

            rocksdb::BlockBasedTableOptions table_options;
            table_options.block_size=16*1024;
            table_options.format_version = 4;
            table_options.index_block_restart_interval = 16;
            table_options.enable_index_compression=false;
            options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
            rocksdb::Status s3 = rocksdb::DB::Open(options, file, &db);
            if (!s3.ok()) {
                std::cerr << "open ssdb3 error:" << s3.ToString() << std::endl;
            }

            
        }


         Status setup(ServerContext *context, ServerReader <SetupRequestMessage> *reader, ExecuteStatus *response) {
            std::cout<<"setup request received"<<std::endl;
            SetupRequestMessage request;
            int index;
            std::string s1, s2;
            int N = 0;
            while (reader->Read(&request)) {
                index = request.index();
                s1 = request.label();
                s2 = request.enc();
                if (index == 0){
                    store(server_db1, s1, s2);
                } else {

                    store(server_db2, s1, s2);
                }
            }
            return Status::OK;
        }

        Status consearch(ServerContext *context, ServerReaderWriter< SearchReply, SearchRequestMessage>* stream) {
            std::cout<<"search request received"<<std::endl;
            //double start, end, time;
            //start = HDXTSU::Cutil::getCurrentTime();
            SearchRequestMessage request;
            std::vector<std::string> result;
            std::string st, e;
            int c, n;
            bool b;
            SearchReply reply;
            std::mutex write_lock;
            auto send_reply = [this, &stream, &reply, &write_lock, &c](const int index, const std::string e) {
               reply.set_index(index);
               reply.set_eid(e);
               write_lock.lock();
               stream->Write(reply);
               write_lock.unlock();

            };

            ThreadPool send_reply_pool(1);

            auto access_job = [this, &send_reply_pool, &send_reply](
                       const std::string st, const int index) {
                std::string e;
                bool b = get(server_db1, st, e);
                if (b){ 
                    send_reply_pool.enqueue(send_reply, index, e);
                } else{
                    return;
                }
            };

            ThreadPool access_pool(8);
            //end = HDXTSU::Cutil::getCurrentTime();
            //time = end - start;
            stream->Read(&request);
            c=request.index();
            int index;
            int st_cnt =0;

             while (stream->Read(&request)) {
                //start = Cutil::getCurrentTime();
                index = request.index();
                st = request.st();
                st_cnt++;
                access_pool.enqueue(access_job, st, index);
                if (st_cnt == c){
                    break;
                }
                //end = Cutil::getCurrentTime();
                //time += (end-start);
            }
            //start = Cutil::getCurrentTime();
            access_pool.join();
            //end = Cutil::getCurrentTime();
            //time += (end-start);
            send_reply_pool.join();

            std::mutex    vec_mutex;

            stream->Read(&request);
            int c1 = request.n();

            std::vector<std::string> ssums(c1, "0000000000000000");
            auto access_job2 = [this, &vec_mutex, &ssums](
                          const std::string label, size_t i) {
                std::string enc, sum;
                bool b = get(server_db2, label, enc);
                if (b == 0){
                    std::cout<<"does not find anything"<<std::endl;
                } else {
                    vec_mutex.lock();
                    sum = ssums.at(i);
                    sum = Cutil::Xor(sum, enc);
                    ssums[i] = sum;
                    vec_mutex.unlock();
                }
            };
            ThreadPool access_pool2(8);




            
            std::string label, enc, d1, d2;
            std::vector<std::string> d1s(c1);
            std::vector<std::string> d2s(c1);


            while (stream->Read(&request)) {
                //start = Cutil::getCurrentTime();
                index = request.index();
                label = request.label();
                if (label == ""){
                    d1 = request.d1();
                    d2 = request.d2();
                    d1s[index] = d1;
                    d2s[index] = d2; 
                    //break;
                } else {
                    access_pool2.enqueue(access_job2, label, index);
                }

                //end = Cutil::getCurrentTime();
                //tmp = end - start;
                //time += (end-start);


            }
            //start = Cutil::getCurrentTime();
            access_pool2.join();
            //end = Cutil::getCurrentTime();
            //tmp = end-start;
            //time += (end-start);
            std::string sum, r;
            std::string s = "0000000000000000";
            for (int i=0; i<c1; i++){
                //start = Cutil::getCurrentTime();
                sum = ssums.at(i);
                d1 = d1s.at(i);
                d2 = d2s.at(i);
                r = Cutil::Xor(d1, sum);
                std::string s1 = Cutil::CTR_AESDecryptStr((CryptoPP::byte *)(r.c_str()), iv_s, d2);
                if (s1 == s){
                    reply.set_index(i);
                    //end = Cutil::getCurrentTime();
                    //time += (end-start);
                    stream->Write(reply);
                } else {
                    //end = Cutil::getCurrentTime();
                    //time += (end-start);
                }

            }
            /*std::ofstream ofile;
            ofile.open("searchtimeserver.txt", std::ios::app);
            ofile <<c1<<" "<< time*1000 << std::endl;*/

            return Status::OK;

        }

        Status tupdate(ServerContext *context, ServerReader <UpdateRequestMessage1> *reader, ExecuteStatus *response) {
            std::cout<<"tupdate request received"<<std::endl;
            UpdateRequestMessage1 request;
            std::string s1, s2;
             while (reader->Read(&request)) {
                s1 = request.ut();
                s2 = request.e();
                store(server_db1, s1, s2);
            }
            return Status::OK;
        }
        

        Status evict(ServerContext *context, ServerReader <EvictRequestMessage> *reader, ExecuteStatus *response) {
            std::cout<<"evict request received"<<std::endl;
            EvictRequestMessage request;
            std::string index;
            std::string s1, s2, e;
            bool b;
            int N = 0;
            std::cout<<"number of tokens1: "<<N<<std::endl;
            rocksdb::DB *tmpdb;
            std::string tmpstr = "/tmp/mytmpdb" +std::to_string(num_tmp);
            open_DB(tmpdb, tmpstr);
            while (reader->Read(&request)) {
                index = request.index();
                s1 = request.label();
                s2 = request.enc();
                if (index == "1"){
                    store(tmpdb, s1, s2);
                    N++;
                } else {
                    std::cout<<"number of tokens: "<<N<<std::endl;
                    rocksdb::Iterator *it = server_db2->NewIterator(rocksdb::ReadOptions());
                    rocksdb::Iterator *it2 = tmpdb->NewIterator(rocksdb::ReadOptions());
                    std::string skey1, skey2;
                    std::string value1, value2, value;
                    int t=0;
                    it2->SeekToFirst();
                    skey2 = it2->key().ToString();
                    value2 = it2->value().ToString();
                    for (it->SeekToFirst(); it->Valid(); it->Next()) {
                        //std::cout<<t<<std::endl;
                        skey1 = it->key().ToString();
                        if (skey1 == skey2){
                            t++;
                            value1 = it->value().ToString();
                            value = Cutil::Xor(value1, value2);
                            store(server_db2, skey1, value);
                            it2->Next();
                            if (it2->Valid()){
                                skey2 = it2->key().ToString();
                                value2 = it2->value().ToString();
                            } else{
                                break;
                            }
                        } else{
                            continue;
                        }

                    }
                    std::cout<<"number of matched entries: "<<t<<std::endl;
                    delete tmpdb;
                    num_tmp++;
                }
            }
            return Status::OK;
        }


        


    };

}

rocksdb::DB *HDXTSU::HDXTSUServiceImpl::server_db1;
rocksdb::DB *HDXTSU::HDXTSUServiceImpl::server_db2;


void RunServer(std::string db_path1, std::string db_path2) {
    std::string server_address("0.0.0.0:50051");
    HDXTSU::HDXTSUServiceImpl service(db_path1, db_path2);
    ServerBuilder builder;
    builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout<<"Server listening on " << server_address << std::endl;
    server->Wait();
}

#endif
