//#include "SSE.server.h"
#include "NAIVE.server.h"

int main(int argc, char *argv[]) {
    //SSE::logger::set_severity(SSE::logger::INFO);
    /*if (argc < 5) {
        std::cerr << "argc error" << std::endl;
        exit(-1);
    }*/
    RunServer(std::string(argv[1]));
}


