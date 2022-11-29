
#include <stdio.h>

#include <grpc++/grpc++.h>
#include "HDXTSU.grpc.pb.h"
#include "HDXTSU.client.h"
#include "crypto.util.h"

using namespace std;

int maxd = 3000;
int maxw = 10000;
int main(int argc, char **argv) {

    std::string client_db = std::string(argv[1]);
    std::string client_cache = std::string(argv[2]);
    HDXTSU::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()), client_db, client_cache);
    std::string function = std::string(argv[3]);
    if (function == "setup"){
        client.setup("../HDXT/test.txt", maxd, maxw);

    } else if (function=="consearch"){
        vector<string> keywords;
        for (int i=4; i<argc; i++){
            keywords.push_back(string(argv[i]));
        }
        unordered_set<string> result;
        //ofstream ofile;
        //ofile.open("susearchtimenetwork1.txt", ios::app);
        //double start = HDXTSU::Cutil::getCurrentTime();
        int r = client.consearch(keywords, result);
        //double end = HDXTSU::Cutil::getCurrentTime();
        //ofile <<r<<" "<<(end - start)*1000 << endl;
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } else if (function == "searchtrace"){
        vector<string> keywords = {"keyword1", "keyword2", "keyword3", "keyword4", "keyword5", "keyword6", "keyword7", "keyword8", "keyword9", "1keyword10"};
        client.addkeywords(keywords, maxd);
        //std::ofstream OsWrite1("update.txt",std::ofstream::app);
         //std::ofstream OsWrite2("susearchtimenetwork3.txt",std::ofstream::app);
        FILE *fp;
        std::string file = "../HDXT/traces.txt";
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
        std::vector<std::pair<std::string, int>> updates;
        std::string function, op, ind, keyword;
        while (fgets(s1, 100, fp)){
            sscanf(s1, "%d %s %s %d", &upds, s2, s3, &id);
            function  = s2;
            keyword = s3;
            if (function == "add"){
                op = "1";
                std::pair<std::string, int> p(op+keyword, id);
                updates.push_back(p); 
            } else if (function == "del"){
                op = "0";
                std::pair<std::string, int> p(op+keyword, id);
                updates.push_back(p); 
            } else if (function == "search"){
                //double start =  HDXTSU::Cutil::Cutil::getCurrentTime();
                client.updatetrace(updates);
               /* double end =  HDXTSU::Cutil::Cutil::getCurrentTime();
                sum_upd+=updates.size();
                sum_time+=(end-start)*1000;
                OsWrite1<<sum_upd << " "<<sum_time<<std::endl;*/
                updates.clear();
                std::unordered_set <std::string> result;
                //start = HDXTSU::Cutil::getCurrentTime();
                int r = client.consearch(keywords, result); 
                //end = HDXTSU::Cutil::getCurrentTime();
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

