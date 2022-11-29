#ifndef NAIVE_SERVER_H
#define NAIVE_SERVER_H
#include <grpc++/grpc++.h>
#include "NAIVE.grpc.pb.h"
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

namespace NAIVE {
    class NAIVEServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *server_db1;

    public:
        NAIVEServiceImpl(const std::string db_path) {
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
            rocksdb::Status s1 = rocksdb::DB::Open(options, db_path, &server_db1);
            if (!s1.ok()) {
                std::cerr << "open ssdb1 error:" << s1.ToString() << std::endl;
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


         Status setup(ServerContext *context, ServerReader <SetupRequestMessage> *reader, ExecuteStatus *response) {
            std::cout<<"setup request received"<<std::endl;
            SetupRequestMessage request;
            int index;
            std::string s1, s2;
            int N = 0;
            while (reader->Read(&request)) {
                s1 = request.label();
                s2 = request.enc();
                store(server_db1, s1, s2);
            }
            return Status::OK;
        }

        Status consearch(ServerContext *context, ServerReaderWriter< SearchReply, SearchRequestMessage>* stream) {
            std::cout<<"search request received"<<std::endl;
            //double start, end, time;
            //start = NAIVE::Cutil::getCurrentTime();
            SearchRequestMessage request;
            std::vector<std::string> result;
            std::string st, e;
            int c, n;
            bool b;
            SearchReply reply;

        
            std::mutex write_lock;


            

            auto send_reply = [this, &stream, &reply, &write_lock, &c](const int index1, const int index2, const std::string e) {
               reply.set_index1(index1);
               reply.set_index2(index2);
               reply.set_eid(e);
               write_lock.lock();
               stream->Write(reply);
               write_lock.unlock();

            };

            ThreadPool send_reply_pool(1);


            auto access_job = [this, &send_reply_pool, &send_reply](
                       const int index1, const int index2, const std::string st) {
                std::string e;
                bool b = get(server_db1, st, e);
                if (b){ 
                    send_reply_pool.enqueue(send_reply, index1, index2, e);
                } else{
                    std::cout<<"could not find "<<index1<<" "<<index2<<" entry"<<std::endl;
                    return;
                }
            };

            ThreadPool access_pool(8);
            int index1, index2;

            //end = NAIVE::Cutil::getCurrentTime();
            //time = end - start;

             while (stream->Read(&request)) {
                //start = Cutil::getCurrentTime();
                index1 = request.index1();
                index2 = request.index2();
                st = request.st();
                access_pool.enqueue(access_job, index1, index2, st);

                //end = Cutil::getCurrentTime();
                //tmp = end - start;
                //time += (end - start);
            }

            //start = NAIVE::Cutil::getCurrentTime();
            access_pool.join();
            //end = NAIVE::Cutil::getCurrentTime();
            //time += (end - start);
            send_reply_pool.join();

            /*std::ofstream ofile;
            ofile.open("naivesearchtimeserver.txt", std::ios::app);
            ofile << time*1000 << std::endl;*/

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

        


    };

}

rocksdb::DB *NAIVE::NAIVEServiceImpl::server_db1;

void RunServer(std::string db_path) {
    std::string server_address("0.0.0.0:50051");
    NAIVE::NAIVEServiceImpl service(db_path);
    ServerBuilder builder;
    builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr <Server> server(builder.BuildAndStart());
    std::cout<<"Server listening on " << server_address << std::endl;
    //SSE::logger::log(SSE::logger::INFO) << "Server listening on " << server_address << std::endl;
    server->Wait();
}

#endif // NAIVE_SERVER_H
