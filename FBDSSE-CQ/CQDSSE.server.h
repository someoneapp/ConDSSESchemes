#ifndef CQDSSE_SERVER_H
#define CQDSSE_SERVER_H
#include <grpc++/grpc++.h>
#include "CQDSSE.grpc.pb.h"
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

namespace CQDSSE {
    class CQDSSEServiceImpl final : public RPC::Service {
    private:
        static rocksdb::DB *server_db1;

    public:
        CQDSSEServiceImpl(const std::string db_path) {
            signal(SIGINT, abort);
            rocksdb::Options options;
            options.create_if_missing = true;
            options.max_background_compactions = 4;
            options.max_subcompactions = 2;
            options.compaction_style=rocksdb::kCompactionStyleLevel;
            options.level_compaction_dynamic_level_bytes=true; //new
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
            std::string s1, s2, s3;
            int N = 0;
            while (reader->Read(&request)) {
                s1 = request.label();
                s2 =request.cst(); 
                s3 = request.enc();
                if (s1 == "len_bs"){
                    store(server_db1, s1, s3);
                } else{
                    store(server_db1, s1, s2+s3);
                }
            }
            std::cout<<"N: "<<N<<std::endl;
            return Status::OK;
        }

        Status consearch(ServerContext *context, ServerReaderWriter< SearchReply, SearchRequestMessage>* stream) {
            std::cout<<"search request received"<<std::endl;
            //double start, end, time;
            //start = Cutil::getCurrentTime();
            SearchRequestMessage request;
            std::vector<std::string> result;
            std::string kw, st, cst, est, e, ut, slen, eh, out, str_sum;
            int c, n, len, i;
            bool b;
            SearchReply reply;
            b = get(server_db1, "len_bs", slen);
            if (b){ 
                char* cs = const_cast<char*>(slen.c_str());
                len = atoi(cs);
            } else{
                std::cout<<"len_bs does not exist";
                return Status::CANCELLED;
            }
            std::string sn(len+1, '0');
            sn[0] = '1';
            sn = sn + "b";
            CryptoPP::Integer int_n(sn.c_str());
            CryptoPP::Integer int_ssum("0");
            //end = Cutil::getCurrentTime();
            //time = end - start;
            while (stream->Read(&request)) {
                //start = Cutil::getCurrentTime();
                kw = request.kw();
                if (kw == ""){
                    break;
                }
                st = request.st();
                c = request.c();
                CryptoPP::Integer int_sum("0");
                for (int i=0; i<c; i++){
                    ut = Cutil::H1(kw+st);
                    if (i==0){
                        out = ut;
                    }
                    b = get(server_db1, ut, est);
                    if (b){ 
                        cst=est.substr(0, 16);
                        e = est.substr(16);
                        CryptoPP::Integer int_e(e.c_str()); 
                        int_sum = (int_sum + int_e)%int_n;
                        delete_entry(server_db1, ut);
                        if (cst == "0000000000000000"){
                            break;
                        }
                        st = Cutil::Xor(cst, Cutil::H2(kw+st));
                    } else{
                        std::cout<<"the entry "<<c<<" does not exist";
                        return Status::CANCELLED;
                    }

                }
                //int_sum转为string
                str_sum = Cutil::Inttostring(int_sum);
                store(server_db1, out, "0000000000000000"+str_sum);
                int_ssum = (int_ssum + int_sum)%int_n;
                //end = Cutil::getCurrentTime();
                //time += (end - start);
            }
            //start = Cutil::getCurrentTime();
            std::string ssum;
            ssum = Cutil::Inttostring(int_ssum);
            reply.set_sum(ssum);
            //end = Cutil::getCurrentTime();
            //time += (end - start);
            stream->Write(reply);

            

            return Status::OK;

        }


         Status tupdate(ServerContext *context, ServerReader <UpdateRequestMessage1> *reader, ExecuteStatus *response) {
            std::cout<<"tupdate request received"<<std::endl;
            UpdateRequestMessage1 request;
            std::string s1, s2, s3;
            while (reader->Read(&request)) {
                s1 = request.label();
                s2 =request.cst(); 
                s3 = request.enc();
                store(server_db1, s1, s2+s3);
            }
            return Status::OK;
        }


        


    };

}

rocksdb::DB *CQDSSE::CQDSSEServiceImpl::server_db1;

void RunServer(std::string db_path) {
    std::string server_address("0.0.0.0:50051");
    CQDSSE::CQDSSEServiceImpl service(db_path);
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

#endif // CQDSSE_SERVER_H
