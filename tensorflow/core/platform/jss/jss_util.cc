#include "tensorflow/core/platform/jss/jss_util.h"

#include <stdlib.h>
#include <malloc.h>
#include <openssl/hmac.h>
#include <math.h>

#include "tensorflow/core/lib/core/errors.h"

namespace tensorflow {
/// make http range string
    Status makeRangeString(uint64 offset, size_t n, string &result) {
        if (result == NULL) {
            return errors::InvalidArgument(std::string("result point is NULL."));
        }
        if (!result.empty()) {
            result.clear();
        }
        std::stringstream ss;
        ss << "bytes=" << offset << "-" << offset + uint64(n) - 1;
        result.append(ss.str());
        return Status::OK();
    }

/// sign string for jss auth
    Status sign(const string *secret_key, const string *input, string *output) {
        // check
        if (!secret_key) { return errors::Internal("secret_key for sign is required."); }
        if (!input) { return errors::Internal("input for sign is required."); }
        if (!output) { return errors::Internal("output for sign is required."); }

        // hmac
        const EVP_MD *engine = EVP_sha1();
        unsigned char buffer[EVP_MAX_MD_SIZE];
        unsigned int buffer_len;

        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, secret_key->c_str(), (int) (secret_key->length()), engine, NULL);
        HMAC_Update(&ctx, (unsigned char *) input->c_str(), input->length()); // input is OK; &input is WRONG !!!
        HMAC_Final(&ctx, (unsigned char *) &buffer, &buffer_len);
        HMAC_CTX_cleanup(&ctx);

        // base64
        size_t size = (size_t) buffer_len * 2;
        size = size > 64 ? size : 64;
        unsigned char *out = (unsigned char *) malloc(size);
        int out_len = EVP_EncodeBlock(out, (unsigned char *) &buffer, buffer_len);

        // set
        output->assign((char *) out, (size_t) out_len);

        // clean
        free(out);
        return Status::OK();
    }

/// sign string for jss auth
    Status get_time_str(string *output) {
        if (!output) {
            return errors::Internal("output for time string is required.");
        }
        const int BUF_SIZE = 64;
        char buf[BUF_SIZE];
        time_t t = time(NULL);
        strftime((char *) &buf, BUF_SIZE, "%a, %d %b %G %T GMT", gmtime(&t));
        output->assign((char *) buf);

        return Status::OK();
    }

    constexpr int64 kNanosecondsPerSecond = 1000 * 1000 * 1000;

    Status parse_time_str(const string &time, int64 *mtime_nsec) {
        struct tm parsed;
        strptime(time.c_str(), "%a, %d %b %Y %T GMT", &parsed);
        *mtime_nsec = timegm(&parsed) * kNanosecondsPerSecond;

        return Status::OK();
    }


/// Reads a long JSON value with the given name from a parent JSON value.
    Status parse_int64_string(const string &str, int64 *result) {
        if (strings::safe_strto64(str.c_str(), result)) {
            return Status::OK();
        }
        return errors::Internal(
                "The string '", str,
                "' in was expected to be a number.");
    }


/// parse bucket and object from jss file path.
    Status parse_bucket_Object(const string &path, string *bucket, string *object) {
        if (path == NULL || path.size() == 0) {
            return errors::Internal("path for input is required.");
        }
        if (path.compare(0, 6, "jss://") != 0) {
            return errors::Internal("path for input not start with \"jss://\".");
        }
        if (!bucket) {
            return errors::Internal("bucket for out is required.");
        }
        int first_pos = (int) path.find('/', 6);
        if (first_pos < 0) {
            bucket->assign(path.substr(6).c_str());
            return Status::OK();
        }
        if (!object) {
            return errors::Internal("object for out is required.");
        }
        bucket->assign(path.substr(6, (unsigned long) first_pos - 6).c_str());
        object->assign(path.substr((unsigned long) first_pos + 1).c_str());

        return Status::OK();
    }
} // namespace tensorflow