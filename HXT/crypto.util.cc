#include "crypto.util.h"

using namespace CryptoPP;

#if __SSE2__
     #include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
    #include <emmintrin.h>              /* SSE2 instructions               */
    typedef __m128i block;
    #define xor_block(x,y)        _mm_xor_si128(x,y)
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__ || USE_AES_NI
    #include <tmmintrin.h>              /* SSSE3 instructions              */
    #define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))
	#else
    static inline block swap_if_le(block b) {
		block a = _mm_shuffle_epi32  (b, _MM_SHUFFLE(0,1,2,3));
		a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2,3,0,1));
		a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2,3,0,1));
		return _mm_xor_si128(_mm_srli_epi16(a,8), _mm_slli_epi16(a,8));
    }
	#endif
	static inline block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		block hi = _mm_load_si128((__m128i *)(KtopStr+0));   /* hi = B A */
		block lo = _mm_loadu_si128((__m128i *)(KtopStr+1));  /* lo = C B */
		__m128i lshift = _mm_cvtsi32_si128(bot);
		__m128i rshift = _mm_cvtsi32_si128(64-bot);
		lo = _mm_xor_si128(_mm_sll_epi64(hi,lshift),_mm_srl_epi64(lo,rshift));
		#if __SSSE3__ || USE_AES_NI
		return _mm_shuffle_epi8(lo,_mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7));
		#else
		return swap_if_le(_mm_shuffle_epi32(lo, _MM_SHUFFLE(1,0,3,2)));
		#endif
	}
	static inline block double_block(block bl) {
		const __m128i mask = _mm_set_epi32(135,1,1,1);
		__m128i tmp = _mm_srai_epi32(bl, 31);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
		bl = _mm_slli_epi32(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}
    
#endif


#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)



#define BPI 8 

namespace HXT {

    std::string Cutil::Xor(const std::string s1, const std::string s2) {
        std::string result = s1;
        if (s1.length() > s2.length()) {
            std::cout << "not sufficient size: " << s1.length() << ", " << s2.length() << std::endl;
            return "";
        }

        for (int i = 0; i < result.length(); i++) {
            result[i] ^= s2[i];
        }
        return result;
    }


    std::string Cutil::H(const std::string message) {
        byte buf[SHA256::DIGESTSIZE];
        SHA256().CalculateDigest(buf, (byte * )(message.c_str()), message.length());
        return std::string((const char *) buf, (size_t) SHA256::DIGESTSIZE);
    }


     std::string Cutil::CTR_AESEncryptStr(const byte *skey, const byte *siv, const std::string plainText){
            std::string outstr;
            try {
                CTR_Mode<AES>::Encryption e;
                e.SetKeyWithIV(skey, AES128_KEY_LEN, siv, (size_t) AES::BLOCKSIZE);
                StringSource ss2(plainText, true, 
                    new StreamTransformationFilter( e,
                    new StringSink(outstr)
                    )     
                );
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in CTR_AESEncryptStr" << e.what() << std::endl;
                exit(1);
            }
            return outstr;
        } 

        std::string Cutil::CTR_AESDecryptStr(const byte *skey, const byte *siv, const std::string cipherText){
            std::string outstr;
            try {
                CTR_Mode<AES>::Decryption e;
                e.SetKeyWithIV(skey, AES128_KEY_LEN, siv, (size_t) AES::BLOCKSIZE);
               StringSource ss2(cipherText, true, 
                    new StreamTransformationFilter( e,
                    new StringSink(outstr)
                    )     
                );
            }
            catch (const CryptoPP::Exception &e) {
                std::cerr << "in CTR_AESDecryptStr" << e.what() << std::endl;
                exit(1);
            }
            return outstr;
        }


    void Cutil::F_p(const std::string s, AES_KEY *key, const Integer& p, Integer& res){
        std::string r = Cutil::F_aesni(key, s.c_str(), s.length(), 2);
        unsigned char *ucr = (unsigned char *)r.c_str();
        std::stringstream bytesHexString;
        bytesHexString << std::hex << std::setfill('0');
        for(int i = 0; i < r.length(); i++) {
            bytesHexString << std::setw(2) << static_cast<int>(ucr[i]);
        }
        std::string hexstring = bytesHexString.str()+"h";
        Integer intr(hexstring.c_str()); 
        Integer element("1");
        Integer tmp = p - element;
        res = element + intr%tmp;
        if (res<element || res>tmp){
            std::cout<<"error"<<std::endl;
        }
    }

    std::string Cutil::Inttostring(const Integer& a){
        std::ostringstream outStream;
        outStream << std::hex<<a;
        return outStream.str();
    }


    void Cutil::generate_salt(unsigned int k, std::vector<unsigned int>& salt){
        const unsigned int predef_salt_count = 128;

        static const unsigned int predef_salt[predef_salt_count] =
                                 {
                                    0xAAAAAAAA, 0x55555555, 0x33333333, 0xCCCCCCCC,
                                    0x66666666, 0x99999999, 0xB5B5B5B5, 0x4B4B4B4B,
                                    0xAA55AA55, 0x55335533, 0x33CC33CC, 0xCC66CC66,
                                    0x66996699, 0x99B599B5, 0xB54BB54B, 0x4BAA4BAA,
                                    0xAA33AA33, 0x55CC55CC, 0x33663366, 0xCC99CC99,
                                    0x66B566B5, 0x994B994B, 0xB5AAB5AA, 0xAAAAAA33,
                                    0x555555CC, 0x33333366, 0xCCCCCC99, 0x666666B5,
                                    0x9999994B, 0xB5B5B5AA, 0xFFFFFFFF, 0xFFFF0000,
                                    0xB823D5EB, 0xC1191CDF, 0xF623AEB3, 0xDB58499F,
                                    0xC8D42E70, 0xB173F616, 0xA91A5967, 0xDA427D63,
                                    0xB1E8A2EA, 0xF6C0D155, 0x4909FEA3, 0xA68CC6A7,
                                    0xC395E782, 0xA26057EB, 0x0CD5DA28, 0x467C5492,
                                    0xF15E6982, 0x61C6FAD3, 0x9615E352, 0x6E9E355A,
                                    0x689B563E, 0x0C9831A8, 0x6753C18B, 0xA622689B,
                                    0x8CA63C47, 0x42CC2884, 0x8E89919B, 0x6EDBD7D3,
                                    0x15B6796C, 0x1D6FDFE4, 0x63FF9092, 0xE7401432,
                                    0xEFFE9412, 0xAEAEDF79, 0x9F245A31, 0x83C136FC,
                                    0xC3DA4A8C, 0xA5112C8C, 0x5271F491, 0x9A948DAB,
                                    0xCEE59A8D, 0xB5F525AB, 0x59D13217, 0x24E7C331,
                                    0x697C2103, 0x84B0A460, 0x86156DA9, 0xAEF2AC68,
                                    0x23243DA5, 0x3F649643, 0x5FA495A8, 0x67710DF8,
                                    0x9A6C499E, 0xDCFB0227, 0x46A43433, 0x1832B07A,
                                    0xC46AFF3C, 0xB9C8FFF0, 0xC9500467, 0x34431BDF,
                                    0xB652432B, 0xE367F12B, 0x427F4C1B, 0x224C006E,
                                    0x2E7E5A89, 0x96F99AA5, 0x0BEB452A, 0x2FD87C39,
                                    0x74B2E1FB, 0x222EFD24, 0xF357F60C, 0x440FCB1E,
                                    0x8BBE030F, 0x6704DC29, 0x1144D12F, 0x948B1355,
                                    0x6D8FD7E9, 0x1C11A014, 0xADD1592F, 0xFB3C712E,
                                    0xFC77642F, 0xF9C4CE8C, 0x31312FB9, 0x08B0DD79,
                                    0x318FA6E7, 0xC040D23D, 0xC0589AA7, 0x0CA5C075,
                                    0xF874B172, 0x0CF914D5, 0x784D3280, 0x4E8CFEBC,
                                    0xC569F575, 0xCDB2A091, 0x2CC016B4, 0x5C5F4421
                                 };

        unsigned long long int random_seed = (0xA5A5A5A5 * 0xA5A5A5A5) + 1;
        std::copy(predef_salt,
                   predef_salt + k,
                   std::back_inserter(salt));

         for (std::size_t i = 0; i < salt.size(); ++i)
         {
            salt[i] = salt[i] * salt[(i + 3) % salt.size()] + static_cast<unsigned int>(random_seed);
         }
    }


    unsigned int Cutil::hash_bf(const unsigned char* begin, std::size_t remaining_length, unsigned int hash)
   {
      const unsigned char* itr = begin;
      unsigned int loop        = 0;

      while (remaining_length >= 8)
      {
         const unsigned int& i1 = *(reinterpret_cast<const unsigned int*>(itr)); itr += sizeof(unsigned int);
         const unsigned int& i2 = *(reinterpret_cast<const unsigned int*>(itr)); itr += sizeof(unsigned int);

         hash ^= (hash <<  7) ^  i1 * (hash >> 3) ^
              (~((hash << 11) + (i2 ^ (hash >> 5))));

         remaining_length -= 8;
      }

      if (remaining_length)
      {
         if (remaining_length >= 4)
         {
            const unsigned int& i = *(reinterpret_cast<const unsigned int*>(itr));

            if (loop & 0x01)
               hash ^=    (hash <<  7) ^  i * (hash >> 3);
            else
               hash ^= (~((hash << 11) + (i ^ (hash >> 5))));

            ++loop;

            remaining_length -= 4;

            itr += sizeof(unsigned int);
         }

         if (remaining_length >= 2)
         {
            const unsigned short& i = *(reinterpret_cast<const unsigned short*>(itr));

            if (loop & 0x01)
               hash ^=    (hash <<  7) ^  i * (hash >> 3);
            else
               hash ^= (~((hash << 11) + (i ^ (hash >> 5))));

            ++loop;

            remaining_length -= 2;

            itr += sizeof(unsigned short);
         }

         if (remaining_length)
         {
            hash += ((*itr) ^ (hash * 0xA5A5A5A5)) + loop;
         }
      }

      return hash;
   }



   double Cutil::getCurrentTime(){
	    double res = 0;
	    struct timeval tv;
	    gettimeofday(&tv, NULL);
	    res += tv.tv_sec;
	    res += (tv.tv_usec/1000000.0);
	    return res;
    }


    static void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
        {
            __m128i x0,x1,x2;
            __m128i *kp = (__m128i *)key;
            kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
            x2 = _mm_setzero_si128();
            EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
            EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
        }

        static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
            unsigned i,j,rnds=ROUNDS(key);
	        const __m128i *sched = ((__m128i *)(key->rd_key));
	        for (i=0; i<nblks; ++i)
	        blks[i] =_mm_xor_si128(blks[i], sched[0]);
	        for(j=1; j<rnds; ++j)
	        for (i=0; i<nblks; ++i)
		        blks[i] = _mm_aesenc_si128(blks[i], sched[j]);
	            for (i=0; i<nblks; ++i)
	            blks[i] =_mm_aesenclast_si128(blks[i], sched[j]);
        }

        static inline void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
            unsigned i,j,rnds=ROUNDS(key);
	        const __m128i *sched = ((__m128i *)(key->rd_key));
	        for (i=0; i<nblks; ++i)
	        blks[i] =_mm_xor_si128(blks[i], sched[0]);
	        for(j=1; j<rnds; ++j)
	        for (i=0; i<nblks; ++i)
		        blks[i] = _mm_aesdec_si128(blks[i], sched[j]);
	        for (i=0; i<nblks; ++i)
	        blks[i] =_mm_aesdeclast_si128(blks[i], sched[j]);
        }
        

        int Cutil::AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
        {
            if (bits == 128) {
                AES_128_Key_Expansion (userKey,key);
            } else {
                std::cout<<"key length needs to be 128 bits"<<std::endl;
            }
            return 0;
        }


        std::string Cutil::F_aesni(AES_KEY    *key,
               const void *e,
               int         e_len, int t)
        {

	        union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
            const block *ep = (block *)e;
            int i = (e_len-1)/16;
            int j = e_len%16;
            block ta[i+1];
            int k =0;
            for (k=0; k<i; k++){
                tmp.bl = zero_block();
		        memcpy(tmp.u8, ep+k, 16);
		        ta[k] = tmp.bl;
            }
            if (j == 0){
                tmp.bl = zero_block();
		        memcpy(tmp.u8, ep+k, 16);
		        ta[k] = tmp.bl;
            } else if (j>0){
                tmp.bl = zero_block();
		        memcpy(tmp.u8, ep+i, j);
		        tmp.u8[j] = (unsigned char)0x80u;
		        ta[k] = tmp.bl;
            }
            AES_ecb_encrypt_blks(ta,i+1, key);
            int length = (i+1)*16;
            char ctp[length];
            memcpy((char *)ctp, &ta, length);
            if (e_len<=16 && t ==1){
                return std::string(ctp, length);
            } else if (e_len>16 && t == 1){
                byte buf[SHA256::DIGESTSIZE];
                SHA256().CalculateDigest(buf, (byte * )(ctp), length);
               return std::string((const char *) buf, 16);
            } else if (t == 2) {
                byte buf[SHA256::DIGESTSIZE];
                SHA256().CalculateDigest(buf, (byte * )(ctp), length);
               return std::string((const char *) buf, (size_t) SHA256::DIGESTSIZE);
            }


        }


}
