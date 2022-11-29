

#include <stdio.h>

#include "Server.storage.h"
#include<iostream>
#include<fstream>
#include<iomanip>
using namespace std;

int d_num = 86386;
int w_num = 188096;
int pair_num = 188096;

// simulate the server storage of various conjunctive DSSE schemes

/*
index.txt should be the inverted index
example:
keyword1 1
keyword1 6
keyword1 9
keyword2 1
keyword2 5
keyword3 9

indexfoc.txt should be the forward index
example:
1 keyword1
1 keyword2
5 keyword2
6 keyword1
9 keyword1
9 keyword3

*/

int main(int argc, char **argv) {

    std::string server_db1 = std::string(argv[1]);
    std::string server_db2 = std::string(argv[2]);
    STORAGE::Client client(server_db1, server_db2);
    std::string scheme = std::string(argv[3]);
    if (scheme == "hdxt"){
        client.hdxt_storage("index.txt", d_num);
    } else if (scheme == "ibtree"){
        client.ibtree_storage(d_num, w_num);
    } else if (scheme == "cnffilter"){
        client.cnffilter_storage("index.txt");
    } else if (scheme == "iex"){
        client.iex_storage("indexdoc.txt");
    } else if (scheme == "fbdssecq"){
        client.fbdssecq_storage("index.txt", d_num, w_num);
    }
}

