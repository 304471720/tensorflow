#include <string>
#include "tensorflow/core/lib/core/status.h"

namespace tensorflow {
    Status makeRangeString(uint64 offset, size_t n, string &result);

    Status sign(const string *secret_key, const string *input, string *output);

    Status get_time_str(string *output);

    Status parse_time_str(const string &time, int64 *mtime_nsec);

    Status parse_int64_string(const string &str, int64 *result);

    Status parse_bucket_Object(const string &path, string *bucket, string *object);
}