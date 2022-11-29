
#include <stdio.h>

#include <grpc++/grpc++.h>
#include "NAIVE.grpc.pb.h"
#include "NAIVE.client.h"
#include "crypto.util.h"
#include<iostream>
#include<fstream>
#include<iomanip>
using namespace std;


int main(int argc, char **argv) {

    std::string client_db = std::string(argv[1]);
    NAIVE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()), client_db);
    std::string function = std::string(argv[2]);
    if (function == "setup"){
        client.setup("../HDXT/test.txt");
    } else if (function=="consearch"){
        vector<string> keywords;
        for (int i=3; i<argc; i++){
            keywords.push_back(string(argv[i]));
        }
        set<string> result;
        //ofstream ofile;
        //ofile.open("naivesearchtimenetwork1.txt", ios::app);
        //double start = NAIVE::Cutil::getCurrentTime();
        int r = client.consearch(keywords, result);
        //double end = NAIVE::Cutil::getCurrentTime();
        //ofile <<r<<" "<<(end - start)*1000 << endl;
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } else if (function == "searchtrace"){
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
        std::vector<std::pair<std::string, std::string>> updates;
        std::string function, op, ind, keyword;
        vector<string> keywords = {"keyword1", "keyword2", "keyword3", "keyword4", "keyword5", "keyword6", "keyword7", "keyword8", "keyword9", "1keyword10"};
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
                //double start =  NAIVE::Cutil::getCurrentTime();
                client.updatetrace(updates);
                //double end =  NAIVE::Cutil::getCurrentTime();
                /*sum_upd+=updates.size();
                sum_time+=(end-start)*1000;
                OsWrite1<<sum_upd << " "<<sum_time<<std::endl;*/
                updates.clear();
                std::set <std::string> result;
                //start = NAIVE::Cutil::getCurrentTime();
                int r = client.consearch(keywords, result); 
                //end = NAIVE::Cutil::getCurrentTime();
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

