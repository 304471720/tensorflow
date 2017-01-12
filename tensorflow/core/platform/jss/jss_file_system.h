/* Copyright 2016 The TensorFlow Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#ifndef TENSORFLOW_CORE_PLATFORM_JSS_FILE_SYSTEM_H_
#define TENSORFLOW_CORE_PLATFORM_JSS_FILE_SYSTEM_H_

#include <string>
#include <vector>
#include "tensorflow/core/lib/core/status.h"
#include "tensorflow/core/platform/cloud/http_request.h"
#include "tensorflow/core/platform/cloud/retrying_file_system.h"
#include "tensorflow/core/platform/file_system.h"

namespace tensorflow {

/// Google Cloud Storage implementation of a file system.
///
/// The clients should use RetryingJssFileSystem defined below,
/// which adds retry logic to JSS operations.
    class JssFileSystem : public FileSystem {
    public:
        JssFileSystem();

        JssFileSystem(std::unique_ptr<JssAuthProvider> auth_provider,
                      std::unique_ptr<HttpRequest::Factory> http_request_factory,
                      size_t read_ahead_bytes, int32 max_upload_attempts);

        Status NewRandomAccessFile(
                const string &filename,
                std::unique_ptr<RandomAccessFile> *result) override;

        Status NewWritableFile(const string &fname,
                               std::unique_ptr<WritableFile> *result) override;

        Status NewAppendableFile(const string &fname,
                                 std::unique_ptr<WritableFile> *result) override;

        Status NewReadOnlyMemoryRegionFromFile(
                const string &filename,
                std::unique_ptr<ReadOnlyMemoryRegion> *result) override;

        Status FileExists(const string &fname) override;

        Status Stat(const string &fname, FileStatistics *stat) override;

        Status GetChildren(const string &dir, std::vector<string> *result) override;

        Status GetMatchingPaths(const string &pattern,
                                std::vector<string> *results) override;

        Status DeleteFile(const string &fname) override;

        Status CreateDir(const string &dirname) override;

        Status DeleteDir(const string &dirname) override;

        Status GetFileSize(const string &fname, uint64 *file_size) override;

        Status RenameFile(const string &src, const string &target) override;

        Status IsDirectory(const string &fname) override;

        Status DeleteRecursively(const string &dirname, int64 *undeleted_files,
                                 int64 *undeleted_dirs) override;

    private:
        /// \brief Checks if the bucket exists. Returns OK if the check succeeded.
        ///
        /// 'result' is set if the function returns OK. 'result' cannot be nullptr.
        Status BucketExists(const string &bucket, bool *result);

        /// \brief Checks if the object exists. Returns OK if the check succeeded.
        ///
        /// 'result' is set if the function returns OK. 'result' cannot be nullptr.
        Status ObjectExists(const string &bucket, const string &object, bool *result);

        /// \brief Checks if the folder exists. Returns OK if the check succeeded.
        ///
        /// 'result' is set if the function returns OK. 'result' cannot be nullptr.
        Status FolderExists(const string &dirname, bool *result);

        /// \brief Internal version of GetChildren with more knobs.
        ///
        /// If 'recursively' is true, returns all objects in all subfolders.
        /// Otherwise only returns the immediate children in the directory.
        ///
        /// If 'include_self_directory_marker' is true and there is a JSS directory
        /// marker at the path 'dir', GetChildrenBound will return an empty string
        /// as one of the children that represents this marker.
        Status GetChildrenBounded(const string &dir, uint64 max_results,
                                  std::vector<string> *result, bool recursively,
                                  bool include_self_directory_marker);

        /// Retrieves file statistics assuming fname points to a JSS object.
        Status StatForObject(const string &bucket, const string &object,
                             FileStatistics *stat);

        Status RenameObject(const string &src, const string &target);

        std::unique_ptr<JssAuthProvider> auth_provider_;
        std::unique_ptr<HttpRequest::Factory> http_request_factory_;

        // The number of bytes to read ahead for buffering purposes in the
        // RandomAccessFile implementation. Defaults to 256Mb.
        const size_t read_ahead_bytes_ = 256 * 1024 * 1024;

        // The max number of attempts to upload a file to JSS using the resumable
        // upload API.
        const int32 max_upload_attempts_ = 5;

        TF_DISALLOW_COPY_AND_ASSIGN(JssFileSystem);
    };

/// Google Cloud Storage implementation of a file system with retry on failures.
    class RetryingJssFileSystem : public RetryingFileSystem {
    public:
        RetryingJssFileSystem()
                : RetryingFileSystem(std::unique_ptr<FileSystem>(new JssFileSystem)) {}
    };

    class JssAuthProvider {
    public:
        JssAuthProvider();

        JssAuthProvider(const string &access_key, const string &access_secret_key, const string &endpoint);

        Status GetToken(HttpRequest *request, string *token,
                        const string *method, const string *date, const string *customHead, const string *resource);

        static Status GetToken(JssAuthProvider *provider, HttpRequest *request, string *token,
                               const string *method, const string *date, const string *customHead,
                               const string *resource);

        const string GetEndPoint();

    private:
        string access_key_;
        string access_secret_key_;
        string endpoint_;
    };

}  // namespace tensorflow

#endif  // TENSORFLOW_CORE_PLATFORM_JSS_FILE_SYSTEM_H_