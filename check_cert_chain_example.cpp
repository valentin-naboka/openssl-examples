#include <openssl/pem.h>

#include <string>
#include <iostream>
#include <memory>
#include <vector>

#define DECLARE_OPENSSL_OBJ_PTR(name) \
using name##_Ptr = std::unique_ptr<name, decltype(&name##_free)>;

DECLARE_OPENSSL_OBJ_PTR(X509);
DECLARE_OPENSSL_OBJ_PTR(X509_STORE);
DECLARE_OPENSSL_OBJ_PTR(X509_STORE_CTX);

std::tuple<X509_Ptr, std::string> read_X509_from_file(const std::string& filename)
{
    using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;
    FilePtr intermediate_cert_file(fopen(filename.c_str(), "r"), &fclose);
    if (!intermediate_cert_file)
    {
        return {X509_Ptr(nullptr, &X509_free), "unable to open file: " + filename + ": " + strerror(errno)};
    }

    X509_Ptr cert(PEM_read_X509(intermediate_cert_file.get(), nullptr, nullptr, nullptr), &X509_free);
    if (!cert)
    {
        return {X509_Ptr(nullptr, &X509_free), "unable to read X509 format from file: " + filename + ": " + strerror(errno)};
    }

    return {std::move(cert), ""};
}

std::tuple<bool, std::string> ssl_certificate_check_signer(const std::string& cert_filename, const std::vector<std::string>& additional_intermediate_certs = {})
{
    X509_STORE_Ptr store(X509_STORE_new(), &X509_STORE_free);
    if (store == nullptr) {
        return {false, "unable to allocate memory for X509_STORE"};
    }

    std::vector<X509_Ptr> additional_certs;

    for(const auto& cert_filename : additional_intermediate_certs)
    {
        auto [cert, err] = read_X509_from_file(cert_filename);
        if(!err.empty())
        {
            return {false, std::move(err)};
        }

        if (X509_STORE_add_cert(store.get(), cert.get()) == 0)
        {
            return {false, "unable to load certificate" + cert_filename + "to store"};
        }

        additional_certs.emplace_back(std::move(cert));
    }

    if (X509_STORE_set_default_paths(store.get()) == 0)
    {
        return {false, "unable to load certificates default paths"};
    }

    if (X509_STORE_set_flags(store.get(), X509_V_FLAG_X509_STRICT) == 0)
    {
        return {false, "unable to set X509_V_FLAG_X509_STRICT flag"};
    }

    X509_STORE_CTX_Ptr store_ctx(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
    if (store_ctx == nullptr)
    {
        return {false, "unable to allocate memory for X509_STORE_CTX"};;
    }

    const auto [cert, err] = read_X509_from_file(cert_filename);
    if(!err.empty())
    {
        return {false, std::move(err)};
    }

    if(X509_STORE_CTX_init(store_ctx.get(), store.get(), cert.get(), nullptr) == 0)
    {
        return {false, "unable to init X509_STORE_CTX"};
    }

    const auto result = X509_verify_cert(store_ctx.get());
    if (result <= 0)
    {
        return {false, X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx.get()))};
    }

    return {true, ""};
}
 
int main(int argc, char **argv)
{
    if(argc < 2)
    {
        std::cout<<std::endl<<"Not enough arguments"<<std::endl;
        std::cout<<std::endl<<"Example: "<<argv[0]<<" cert_to_verify.pem [intermediate_cert.pem...]" <<std::endl;
        return 1;
    }

    std::vector<std::string> additional_certs;
    std::copy(argv+2, argv+argc, std::back_inserter(additional_certs));

    auto [result, err] = ssl_certificate_check_signer(argv[1], additional_certs);
    if (result)
    {
        std::cout<<std::endl<<"Successfully verified"<<std::endl;
        return 0;
    }

    std::cout<<std::endl<<err<<std::endl;
    return 1;
}