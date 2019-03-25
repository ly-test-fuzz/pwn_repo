#include <openssl/evp.h>
#include <openssl/des.h>
#include <stdint.h>
#include <unistd.h>
char key[32]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
char iv[16]="bbbbbbbbbbbbbbbb";


int main()
{
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, 0);
    int sz;
    read(0,&sz,4);
    char* buf = malloc(sz);
    read(0,buf,sz);
    char* ans = malloc(sz+0x100);
    int outlen;
    EVP_CipherUpdate(ctx, ans, &outlen, buf, sz);
    int t = outlen;
    EVP_CipherFinal(ctx, ans+outlen, &outlen);
    write(1,&t,4);
    write(1,ans,t);
    return 0;
}
