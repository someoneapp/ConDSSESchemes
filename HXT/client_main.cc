#include <stdio.h>

#include <grpc++/grpc++.h>
#include "HXT.grpc.pb.h"
#include "HXT.client.h"
#include "crypto.util.h"
#include<iostream>
#include<fstream>
#include<iomanip>
using namespace std;

int N = 50000;
int maxd = 20000;

int main(int argc, char **argv) {

    std::string client_db = std::string(argv[1]);
    HXT::Client client(grpc::CreateChannel("0.0.0.0:50051", grpc::InsecureChannelCredentials()), client_db);
    std::string function = std::string(argv[2]);
    if (function == "setup"){
        client.setup("../HDXT/test.txt", N, maxd);
    } else if (function == "consearch"){
        vector<string> keywords;
        for (int i=3; i<argc; i++){
            keywords.push_back(string(argv[i]));
        }
        unordered_set<string> result;
	    //ofstream ofile;
        //ofile.open("hxtsearchnetwork1.txt", ios::app);
        //double start = HXT::Cutil::getCurrentTime();
        int r = client.consearch(keywords, result);
        //double end = HXT::Cutil::getCurrentTime();
        //ofile <<r<<" "<<end - start<< endl;
        for (auto it = result.begin(); it!=result.end(); it++){
            cout<<*it<<endl;
        }
    } 
    return 0;
}

