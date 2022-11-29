#include <stdio.h>

#include <grpc++/grpc++.h>
#include "HDXT.grpc.pb.h"
#include "HDXT.client.h"
#include "crypto.util.h"
using namespace std;

int maxd = 3000;
int maxw = 10000;

int main(int argc, char **argv) {

    std::string client_db = std::string(argv[1]);
    std::string client_cache = std::string(argv[2]);
    HDXT::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()), client_db, client_cache);
    std::string function = std::string(argv[3]);
    if (function == "setup"){
	    client.setup("test.txt", maxd, maxw);
    } else if (function=="consearch"){
        //std::string commufile = std::string(argv[4]);
        vector<string> keywords;
        for (int i=4; i<argc; i++){
            keywords.push_back(string(argv[i]));
        }
        unordered_set<string> result;
        //ofstream ofile;
        //ofile.open("searchtimenetwork.txt", ios::app);
        //double start = HDXT::Cutil::getCurrentTime();
        int r = client.consearch(keywords, result);
        //double end = HDXT::Cutil::getCurrentTime();
        //ofile <<keywords.size()-1<<" "<<end - start << endl;
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } else if (function=="consearch_commu"){
        std::string commufile = std::string(argv[4]);
        vector<string> keywords;
        for (int i=5; i<argc; i++){
            keywords.push_back(string(argv[i]));
        }
        unordered_set<string> result;
        int r = client.consearch_commu(keywords, result, commufile);
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } else if (function == "searchtrace"){
        vector<string> keywords = {"keyword1", "keyword2", "keyword3", "keyword4", "keyword5", "keyword6", "keyword7", "keyword8", "keyword9", "1keyword10"};
        client.addkeywords(keywords, maxd);
        //std::ofstream OsWrite1("update.txt",std::ofstream::app);
        //std::ofstream OsWrite2("searchtimenetwork.txt",std::ofstream::app);
        FILE *fp;
        std::string file = "traces.txt";
	    fp = fopen(file.c_str(), "r");
   	    if(fp == NULL) {
            perror("open file error");
   	    }
        char s1[100];
        char s2[100];
        char s3[100];
        int id;
        int upds;
        int sum_upd =0;
        int sum_time =0;
        std::vector<std::pair<std::string, std::string>> updates;
        std::string function, op, ind, keyword;
       
        while (fgets(s1, 100, fp)){
            sscanf(s1, "%d %s %s %d", &upds, s2, s3, &id);
            function  = s2;
            keyword = s3;
            if (function == "add"){
                op = "1";
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                std::pair<std::string, std::string> p(op+keyword, ind);
                updates.push_back(p); 
            } else if (function == "del"){
                op = "0";
                ind = std::to_string(100000000 + id);
                ind = ind.substr(1, 8);
                std::pair<std::string, std::string> p(op+keyword, ind);
                updates.push_back(p); 
            } else if (function == "search"){
                //double start =  HDXT::Cutil::Cutil::getCurrentTime();
                client.updatetrace(updates);
                //double end =  HDXT::Cutil::Cutil::getCurrentTime();
                //sum_upd+=updates.size();
                //sum_time+=(end-start)*1000;
                //OsWrite1<<sum_upd << " "<<sum_time<<std::endl;
                updates.clear();
                std::unordered_set <std::string> result;
                //start = HDXT::Cutil::getCurrentTime();
                int r = client.consearch(keywords, result); 
                //end = HDXT::Cutil::getCurrentTime();
                if (r > 0){
                    //OsWrite2<<upds << " "<<(end -start) *1000 <<std::endl;
                    for (auto it = result.begin(); it!=result.end(); it++){
                        cout<<*it<<endl;
                    }
                    std::cout << "search done: " << std::endl;
                    
                } else {
                    std::cout << "search error: " << std::endl;
                }
            }
        }
        fclose(fp);
        //OsWrite1.close();
        //OsWrite2.close();
    }
 

 
 


    

    
    return 0;
}

