
#include <stdio.h>

#include <grpc++/grpc++.h>
#include "CQDSSE.grpc.pb.h"
#include "CQDSSE.client.h"
#include "crypto.util.h"
#include<iostream>
#include<fstream>
#include<iomanip>
using namespace std;

int maxd = 3000;
int maxw = 10000;

int main(int argc, char **argv) {

    std::string client_db = std::string(argv[1]);
    CQDSSE::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()), client_db);
    std::string function = std::string(argv[2]);
    //double start, end;
    if (function == "setup"){
        client.setupcq("../HDXT/test.txt", maxd, maxw);
    } /*else if (function == "update"){
        std::string op = std::string(argv[3]);
        int id = atoi(argv[4]);
        //std::string id = std::string(argv[5]);
        std::unordered_set<std::string> ukeywords;
         for (int i=5; i<argc; i++){
            ukeywords.insert(string(argv[i]));
        }
        client.update(op, id, ukeywords);
    }*/ else if (function=="consearch"){
        vector<string> keywords;
        for (int i=3; i<argc; i++){

            
            keywords.push_back(string(argv[i]));
        }
        unordered_set<string> result;
         //std::string keyword = std::string(argv[3]);
         
         //keywords.push_back("keyword1");
         //keywords.push_back("keyword2");
         //keywords.push_back("keyword3");
        //ofstream ofile;
        //ofile.open("searchtimenetwork4.txt", ios::app);
        //double start = CQDSSE::Cutil::getCurrentTime();
        int r = client.consearch(keywords, result);
        //double end = CQDSSE::Cutil::getCurrentTime();
        //ofile <<keywords.size()-1<<" "<<end - start << endl;
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } else if (function == "searchtrace"){
        /*int d_num = 23643;
        int w_num = 5000;*/
        client.prepare(maxd, maxw);
        //std::ofstream OsWrite1("update_local.txt",std::ofstream::app);
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
        vector<string> keywords = {"keyword1", "keyword2", "keyword3", "keyword4", "keyword5", "keyword6", "keyword7", "keyword8", "keyword9", "1keyword10"};
        while (fgets(s1, 100, fp)){
            sscanf(s1, "%d %s %s %d", &upds, s2, s3, &id);
            function  = s2;
            keyword = s3;
            //std::cout<<function<<" "<<keyword<<" "<<id<<std::endl;
            if (function == "add"){
                op = "1";
                std::pair<std::string, int> p(op+keyword, id);
                updates.push_back(p); 
            } else if (function == "del"){
                op = "0";
                std::pair<std::string, int> p(op+keyword, id);
                updates.push_back(p); 
            } else if (function == "search"){
                //std::cout<<"111111111111111111"<<std::endl;
                //CQDSSE::Client client(grpc::CreateChannel("0.0.0.0:50052", grpc::InsecureChannelCredentials()), client_db, client_cache);
                //double start =  CQDSSE::Cutil::Cutil::getCurrentTime();
                client.updatetrace(updates, maxd);
                //double end =  CQDSSE::Cutil::Cutil::getCurrentTime();
                /*sum_upd+=updates.size();
                sum_time+=(end-start)*1000;
                OsWrite1<<sum_upd << " "<<sum_time<<std::endl;*/
                updates.clear();
                //std::cout<<"222222222222222222222222222"<<std::endl;
                std::unordered_set <std::string> result;
                //int c3, c4;
                //std::string sw;
                //double start = FT_VDSSE::Util::getCurrentTime();
                int r = client.consearch(keywords, result); 
                //double end = FT_VDSSE::Util::getCurrentTime();
                if (r > 0){
                    //OsWrite1<<upds << " "<<(end -start) *1000 <<std::endl;
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
    }
 
 

 
 


    

    
    return 0;
}

