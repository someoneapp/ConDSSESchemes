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

namespace NAIVE {

    std::string Cutil::Xor(const std::string s1, const std::string s2) {
        // std::cout<< "in len = "<< s1.length()<<", s1 = "<<s1<<std::endl;
        /*if (s1 == ""){
            return s2;
        }*/
        std::string result = s1;
        if (s1.length() > s2.length()) {
            //ERROR
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
               int         e_len, int option)
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
            if (e_len<=16 && option ==1){
                return std::string(ctp, length);
                //hash =ctp;
            } else if (e_len>16 && option == 1){
                byte buf[SHA256::DIGESTSIZE];
                SHA256().CalculateDigest(buf, (byte * )(ctp), length);
                //memcpy((char *)hash, buf, length);
               return std::string((const char *) buf, 16);
            } else if (option == 2) {
                byte buf[SHA256::DIGESTSIZE];
                SHA256().CalculateDigest(buf, (byte * )(ctp), length);
                //memcpy((char *)hash, buf, length);
               return std::string((const char *) buf, (size_t) SHA256::DIGESTSIZE);
            }


        }

}
