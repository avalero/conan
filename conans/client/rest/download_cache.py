import os
import shutil
import logging

from threading import Lock

from six.moves.urllib_parse import urlsplit, urlunsplit, urlparse

from conans.client.tools.files import check_md5, check_sha1, check_sha256
from conans.errors import ConanException
from conans.util.files import mkdir
from conans.util.locks import SimpleLock
from conans.util.sha import sha256 as sha256_sum
from artifactory import ArtifactoryPath

# Start programming


class CachedFileDownloader(object):
    _thread_locks = {}  # Needs to be shared among all instances

    def __init__(self, cache_folder, remote_cache_url, file_downloader, user_download=False):
        self._cache_folder = cache_folder
        self._file_downloader = file_downloader
        self._user_download = user_download

        # check if url is well constructed, if not set to None

        if bool(urlparse(remote_cache_url).netloc):
            self._remote_cache_url = remote_cache_url
        else:
            self._remote_cache_url = None

    @staticmethod
    def _check_checksum(cache_path, md5, sha1, sha256):
        if md5:
            check_md5(cache_path, md5)
        if sha1:
            check_sha1(cache_path, sha1)
        if sha256:
            check_sha256(cache_path, sha256)

    def download(self, url, file_path=None, auth=None, retry=None, retry_wait=None, overwrite=False,
                 headers=None, md5=None, sha1=None, sha256=None):
        """ compatible interface of FileDownloader + checksum
        """

        checksum = sha256 or sha1 or md5
        # If it is a user download, it must contain a checksum
        assert (not self._user_download) or (self._user_download and checksum)
        h = self._get_hash(url, checksum)
        lock = os.path.join(self._cache_folder, "locks", h)
        cached_path = os.path.join(self._cache_folder, h)
        with SimpleLock(lock):
            # Once the process has access, make sure multithread is locked too
            # as SimpleLock doesn't work multithread
            thread_lock = self._thread_locks.setdefault(lock, Lock())
            thread_lock.acquire()
            try:
                if not os.path.exists(cached_path):
                    # try to download from remote cache artifactory
                    try:
                        # if remote_cache is None it will just raise an Exception and go on. No need to check.
                        # it's easier to ask for forgiveness than permission

                        # I don't really like this, I should refactor download to pass base url and path
                        try:
                            remote_url = ((self._remote_cache_url or "") +
                                          file_path[(file_path.find("data") + len("data")):]
                                          ).replace("//", "/").replace("http:/", "http://")
                            print("remote_url ", remote_url)

                        except Exception:
                            print("Error constructing remote_url")

                        # auth hardcoded, feo, feo. The best of me wants to put it on conan.conf
                        self._file_downloader.download(
                            remote_url, cached_path, ('admin', '12345678'), retry, retry_wait, overwrite, headers)
                        self._check_checksum(cached_path, md5, sha1, sha256)

                    except Exception as e:
                        if os.path.exists(cached_path):
                            os.remove(cached_path)
                        # if not on remote cache Artifcatory, try to download from url
                        try:
                            # print("trying to download from ", url)
                            self._file_downloader.download(url, cached_path, auth, retry, retry_wait,
                                                           overwrite, headers)
                            self._check_checksum(cached_path, md5, sha1, sha256)
                        except Exception as e:
                            print("FAILURE: ", e)
                            if os.path.exists(cached_path):
                                os.remove(cached_path)
                            raise
                else:
                    # specific check for corrupted cached files, will raise, but do nothing more
                    # user can report it or "rm -rf cache_folder/path/to/file"
                    try:
                        self._check_checksum(cached_path, md5, sha1, sha256)
                    except ConanException as e:
                        raise ConanException("%s\nCached downloaded file corrupted: %s"
                                             % (str(e), cached_path))

                if file_path is not None:
                    file_path = os.path.abspath(file_path)
                    mkdir(os.path.dirname(file_path))
                    shutil.copy2(cached_path, file_path)

                    # upload to remote artifact
                    remote_file_path = file_path[(file_path.find("data") + len("data")):]
                    remote_path = remote_file_path[:remote_file_path.rfind("/")]

                    path = (self._remote_cache_url + remote_path).replace("//",
                                                                          "/").replace("http:/", "http://")

                    artifactory_path = ArtifactoryPath(path, auth=('admin', '12345678'))

                    if not artifactory_path.exists():
                        artifactory_path.mkdir()

                    artifactory_path.deploy_file(file_path)

                else:
                    with open(cached_path, 'rb') as handle:
                        tmp = handle.read()
                    return tmp

            finally:
                thread_lock.release()

    def _get_hash(self, url, checksum=None):
        """ For Api V2, the cached downloads always have recipe and package REVISIONS in the URL,
        making them immutable, and perfect for cached downloads of artifacts. For V2 checksum
        will always be None.
        For ApiV1, the checksum is obtained from the server via "get_snapshot()" methods, but
        the URL in the apiV1 contains the signature=xxx for signed urls, but that can change,
        so better strip it from the URL before the hash
        """
        urltokens = urlsplit(url)
        # append empty query and fragment before unsplit
        if not self._user_download:  # removes ?signature=xxx
            url = urlunsplit(urltokens[0:3]+("", ""))
        if checksum is not None:
            url += checksum
        h = sha256_sum(url.encode())
        return h
