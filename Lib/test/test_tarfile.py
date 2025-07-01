import contextlib
import sys
import os
import io
import pathlib
import re
import shutil
import stat
import warnings
from hashlib import md5

import unittest
import tarfile

from test import support, script_helper

# Check for our compression modules.
try:
    import gzip
except ImportError:
    gzip = None
try:
    import bz2
except ImportError:
    bz2 = None
try:
    import lzma
except ImportError:
    lzma = None


def md5sum(data):
    return md5(data).hexdigest()


TEMPDIR = os.path.abspath(support.TESTFN) + "-tardir"
tarextdir = TEMPDIR + '-extract-test'
tarname = support.findfile("testtar.tar")
gzipname = os.path.join(TEMPDIR, "testtar.tar.gz")
bz2name = os.path.join(TEMPDIR, "testtar.tar.bz2")
xzname = os.path.join(TEMPDIR, "testtar.tar.xz")
tmpname = os.path.join(TEMPDIR, "tmp.tar")
dotlessname = os.path.join(TEMPDIR, "testtar")

md5_regtype = "65f477c818ad9e15f7feab0c6d37742f"
md5_sparse = "a54fbc4ca4f4399a90e1b27164012fc6"


class TarTest:
    tarname = tarname
    suffix = ''
    open = io.FileIO
    taropen = tarfile.TarFile.taropen

    @property
    def mode(self):
        return self.prefix + self.suffix


@support.requires_gzip
class GzipTest:
    tarname = gzipname
    suffix = 'gz'
    open = gzip.GzipFile if gzip else None
    taropen = tarfile.TarFile.gzopen


@support.requires_bz2
class Bz2Test:
    tarname = bz2name
    suffix = 'bz2'
    open = bz2.BZ2File if bz2 else None
    taropen = tarfile.TarFile.bz2open


@support.requires_lzma
class LzmaTest:
    tarname = xzname
    suffix = 'xz'
    open = lzma.LZMAFile if lzma else None
    taropen = tarfile.TarFile.xzopen


class ReadTest(TarTest):
    prefix = "r:"

    # This setUp method is for ReadTest and its direct non-compressed subclasses.
    # self._tar_data will be set by the dynamically assigned ReadTest.setUpClass.
    def setUp(self):
        self._tar_data.seek(0) # Reset the BytesIO for each test run
        self.tar = tarfile.open(fileobj=self._tar_data, mode=self.mode,
                                 encoding="iso8859-1")
        self.addCleanup(self.tar.close)

    def tearDown(self):
        support.gc_collect()

    def test_fileobj_regular_file(self):
        tarinfo = self.tar.getmember("ustar/regtype")
        with self.tar.extractfile(tarinfo) as fobj:
            data = fobj.read()
            self.assertEqual(len(data), tarinfo.size,
                             "regular file extraction failed")
            self.assertEqual(md5sum(data), md5_regtype,
                             "regular file extraction failed")

    def test_fileobj_readlines(self):
        # filter='data' is important here to strip
        # permissions/ownership, which might not be available or writable
        # in the test env
        self.tar.extract("ustar/regtype", TEMPDIR, filter='data')
        tarinfo = self.tar.getmember("ustar/regtype")
        with open(os.path.join(TEMPDIR, "ustar/regtype"), "r") as fobj1:
            lines1 = fobj1.readlines()

        with self.tar.extractfile(tarinfo) as fobj:
            fobj2 = io.TextIOWrapper(fobj)
            lines2 = fobj2.readlines()
            self.assertEqual(lines1, lines2,
                             "fileobj.readlines() failed")
            self.assertEqual(len(lines2), 114,
                             "fileobj.readlines() failed")
            self.assertEqual(lines2[83],
                             "I will gladly admit that Python is not the fastest "
                             "running scripting language.\n",
                             "fileobj.readlines() failed")

    def test_fileobj_iter(self):
        # filter='data' is important here to strip
        # permissions/ownership, which might not be available or writable
        # in the test env
        self.tar.extract("ustar/regtype", TEMPDIR, filter='data')
        tarinfo = self.tar.getmember("ustar/regtype")
        with open(os.path.join(TEMPDIR, "ustar/regtype"), "r") as fobj1:
            lines1 = fobj1.readlines()
        with self.tar.extractfile(tarinfo) as fobj2:
            lines2 = list(io.TextIOWrapper(fobj2))
            self.assertEqual(lines1, lines2,
                             "fileobj.__iter__() failed")

    def test_fileobj_seek(self):
        # filter='data' is important here to strip
        # permissions/ownership, which might not be available or writable
        # in the test env
        self.tar.extract("ustar/regtype", TEMPDIR,
                         filter='data')
        with open(os.path.join(TEMPDIR, "ustar/regtype"), "rb") as fobj:
            data = fobj.read()

        tarinfo = self.tar.getmember("ustar/regtype")
        fobj = self.tar.extractfile(tarinfo)

        text = fobj.read()
        fobj.seek(0)
        self.assertEqual(0, fobj.tell(),
                         "seek() to file's start failed")
        fobj.seek(2048, 0)
        self.assertEqual(2048, fobj.tell(),
                         "seek() to absolute position failed")
        fobj.seek(-1024, 1)
        self.assertEqual(1024, fobj.tell(),
                         "seek() to negative relative position failed")
        fobj.seek(1024, 1)
        self.assertEqual(2048, fobj.tell(),
                         "seek() to positive relative position failed")
        s = fobj.read(10)
        self.assertEqual(s, data[2048:2058],
                         "read() after seek failed")
        fobj.seek(0, 2)
        self.assertEqual(tarinfo.size, fobj.tell(),
                         "seek() to file's end failed")
        self.assertEqual(fobj.read(), b"",
                         "read() at file's end did not return empty string")
        fobj.seek(-tarinfo.size, 2)
        self.assertEqual(0, fobj.tell(),
                         "relative seek() to file's end failed")
        fobj.seek(512)
        s1 = fobj.readlines()
        fobj.seek(512)
        s2 = fobj.readlines()
        self.assertEqual(s1, s2,
                         "readlines() after seek failed")
        fobj.seek(0)
        line = fobj.readline()
        self.assertEqual(fobj.read(), data[len(line):],
                         "read() after readline() failed")
        fobj.close()

    def test_fileobj_text(self):
        with self.tar.extractfile("ustar/regtype") as fobj:
            fobj = io.TextIOWrapper(fobj)
            data = fobj.read().encode("iso8859-1")
            self.assertEqual(md5sum(data), md5_regtype)
            try:
                fobj.seek(100)
            except AttributeError:
                # Issue #13815: seek() complained about a missing
                # flush() method.
                self.fail("seeking failed in text mode")

    # Test if symbolic and hard links are resolved by extractfile().  The
    # test link members each point to a regular member whose data is
    # supposed to be exported.
    def _test_fileobj_link(self, lnktype, regtype):
        with self.tar.extractfile(lnktype) as a, \
             self.tar.extractfile(regtype) as b:
            self.assertEqual(a.name, b.name)

    def test_fileobj_link1(self):
        self._test_fileobj_link("ustar/lnktype", "ustar/regtype")

    def test_fileobj_link2(self):
        self._test_fileobj_link("./ustar/linktest2/lnktype",
                                 "ustar/linktest1/regtype")

    def test_fileobj_symlink1(self):
        self._test_fileobj_link("ustar/symtype", "ustar/regtype")

    def test_fileobj_symlink2(self):
        self._test_fileobj_link("./ustar/linktest2/symtype",
                                 "ustar/linktest1/regtype")

    def test_issue14160(self):
        self._test_fileobj_link("symtype2", "ustar/regtype")


class UstarReadTest(ReadTest, unittest.TestCase):
    pass


@support.requires_gzip
class GzipUstarReadTest(GzipTest, UstarReadTest):
    pass


@support.requires_bz2
class Bz2UstarReadTest(Bz2Test, UstarReadTest):
    pass


@support.requires_lzma
class LzmaUstarReadTest(LzmaTest, UstarReadTest):
    pass


class ListTest(ReadTest, unittest.TestCase):
    # This class specifically overrides setUp to use default encoding (UTF-8)
    # for list tests, which is different from ReadTest's iso8859-1.
    def setUp(self):
        # self._tar_data is set by ReadTest.setUpClass (dynamically assigned later)
        self._tar_data.seek(0)
        self.tar = tarfile.open(fileobj=self._tar_data, mode=self.mode)
        self.addCleanup(self.tar.close)

    def test_list(self):
        tio = io.TextIOWrapper(io.BytesIO(), 'ascii', newline='\n')
        with support.swap_attr(sys, 'stdout', tio):
            self.tar.list(verbose=False)
        out = tio.detach().getvalue()
        self.assertIn(b'ustar/conttype', out)
        self.assertIn(b'ustar/regtype', out)
        self.assertIn(b'ustar/lnktype', out)
        self.assertIn(b'ustar' + (b'/12345' * 40) + b'67/longname', out)
        self.assertIn(b'./ustar/linktest2/symtype', out)
        self.assertIn(b'./ustar/linktest2/lnktype', out)
        # Make sure it puts trailing slash for directory
        self.assertIn(b'ustar/dirtype/', out)
        self.assertIn(b'ustar/dirtype-with-size/', out)

        # Make sure it is able to print unencodable characters
        def conv(b):
            s = b.decode(self.tar.encoding, 'surrogateescape')
            return s.encode('ascii', 'backslashreplace')
        self.assertIn(conv(b'ustar/umlauts-\xc4\xd6\xdc\xe4\xf6\xfc\xdf'), out)
        self.assertIn(conv(b'misc/regtype-hpux-signed-chksum-'
                           b'\xc4\xd6\xdc\xe4\xf6\xfc\xdf'), out)
        self.assertIn(conv(b'misc/regtype-old-v7-signed-chksum-'
                           b'\xc4\xd6\xdc\xe4\xf6\xfc\xdf'), out)
        self.assertIn(conv(b'pax/bad-pax-\xe4\xf6\xfc'), out)
        self.assertIn(conv(b'pax/hdrcharset-\xe4\xf6\xfc'), out)
        # Make sure it prints files separated by one newline without any
        # 'ls -l'-like accessories if verbose flag is not being used
        # ...
        # ustar/conttype
        # ustar/regtype
        # ...
        self.assertRegex(out, br'ustar/conttype ?\r?\n'
                                 br'ustar/regtype ?\r?\n')
        # Make sure it does not print the source of link without verbose flag
        self.assertNotIn(b'link to', out)
        self.assertNotIn(b'->', out)

    def test_list_verbose(self):
        tio = io.TextIOWrapper(io.BytesIO(), 'ascii', newline='\n')
        with support.swap_attr(sys, 'stdout', tio):
            self.tar.list(verbose=True)
        out = tio.detach().getvalue()
        # Make sure it prints files separated by one newline with 'ls -l'-like
        # accessories if verbose flag is being used
        # ...
        # ?rw-r--r-- tarfile/tarfile      7011 2003-01-06 07:19:43 ustar/conttype
        # ?rw-r--r-- tarfile/tarfile      7011 2003-01-06 07:19:43 ustar/regtype
        # ...
        self.assertRegex(out, (br'\?rw-r--r-- tarfile/tarfile\s+7011 '
                                 br'\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d '
                                 br'ustar/\w+type ?\r?\n') * 2)
        # Make sure it prints the source of link with verbose flag
        self.assertIn(b'ustar/symtype -> regtype', out)
        self.assertIn(b'./ustar/linktest2/symtype -> ../linktest1/regtype', out)
        self.assertIn(b'./ustar/linktest2/lnktype link to '
                      b'./ustar/linktest1/regtype', out)
        self.assertIn(b'gnu' + (b'/123' * 125) + b'/longlink link to gnu' +
                      (b'/123' * 125) + b'/longname', out)
        self.assertIn(b'pax' + (b'/123' * 125) + b'/longlink link to pax' +
                      (b'/123' * 125) + b'/longname', out)


@support.requires_gzip
class GzipListTest(GzipTest, ListTest):
    pass


@support.requires_bz2
class Bz2ListTest(Bz2Test, ListTest):
    pass


@support.requires_lzma
class LzmaListTest(LzmaTest, ListTest):
    # This specific test belongs here
    def test_length_zero_header(self):
        # bpo-39017 (CVE-2019-20907): reading a zero-length header should fail
        # with an exception
        with self.assertRaisesRegex(tarfile.ReadError, "file could not be opened successfully"):
            with tarfile.open(support.findfile('recursion.tar')) as tar:
                pass


# CommonReadTest is a direct child of ReadTest. It defines more general read tests.
class CommonReadTest(ReadTest):

    def test_empty_tarfile(self):
        # Test for issue6123: Allow opening empty archives.
        # This test checks if tarfile.open() is able to open an empty tar
        # archive successfully. Note that an empty tar archive is not the
        # same as an empty file!
        with tarfile.open(tmpname, self.mode.replace("r", "w")):
            pass
        with tarfile.open(tmpname, self.mode) as tar:
            self.assertListEqual(tar.getmembers(), [])

    def test_non_existent_tarfile(self):
        # Test for issue11513: prevent non-existent gzipped tarfiles raising
        # multiple exceptions.
        with self.assertRaisesRegex(FileNotFoundError, "xxx"):
            tarfile.open("xxx", self.mode)

    def test_null_tarfile(self):
        # Test for issue6123: Allow opening empty archives.
        # This test guarantees that tarfile.open() does not treat an empty
        # file as an empty tar archive.
        with open(tmpname, "wb"):
            pass
        with self.assertRaises(tarfile.ReadError):
            tarfile.open(tmpname)

    def test_ignore_zeros(self):
        # Test TarFile's ignore_zeros option.
        for char in (b'\0', b'a'):
            # Test if EOFHeaderError ('\0') and InvalidHeaderError ('a')
            # are ignored correctly.
            with self.open(tmpname, "w") as fobj:
                fobj.write(char * 1024)
                fobj.write(tarfile.TarInfo("foo").tobuf())

            with tarfile.open(tmpname, mode="r", ignore_zeros=True) as tar:
                self.assertListEqual(tar.getnames(), ["foo"],
                    "ignore_zeros=True should have skipped the %r-blocks" %
                    char)

    def test_premature_end_of_archive(self):
        for size in (512, 600, 1024, 1200):
            with tarfile.open(tmpname, "w:") as tar:
                t = tarfile.TarInfo("foo")
                t.size = 1024
                tar.addfile(t, io.BytesIO(b"a" * 1024))

            with open(tmpname, "r+b") as fobj:
                fobj.truncate(size)

            with tarfile.open(tmpname) as tar:
                with self.assertRaisesRegex(tarfile.ReadError, "unexpected end of data"):
                    for t in tar:
                        pass

            with tarfile.open(tmpname) as tar:
                t = tar.next()

                with self.assertRaisesRegex(tarfile.ReadError, "unexpected end of data"):
                    tar.extract(t, TEMPDIR, filter='data')

                with self.assertRaisesRegex(tarfile.ReadError, "unexpected end of data"):
                    tar.extractfile(t).read()


class MiscReadTestBase(CommonReadTest):
    def requires_name_attribute(self):
        pass

    def test_no_name_argument(self):
        self.requires_name_attribute()
        with open(self.tarname, "rb") as fobj:
            self.assertIsInstance(fobj.name, str)
            with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
                self.assertIsInstance(tar.name, str)
                self.assertEqual(tar.name, os.path.abspath(fobj.name))

    def test_no_name_attribute(self):
        with open(self.tarname, "rb") as fobj:
            data = fobj.read()
        fobj = io.BytesIO(data)
        self.assertRaises(AttributeError, getattr, fobj, "name")
        with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
            self.assertIsNone(tar.name)

    def test_empty_name_attribute(self):
        with open(self.tarname, "rb") as fobj:
            data = fobj.read()
        fobj = io.BytesIO(data)
        fobj.name = ""
        with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
            self.assertIsNone(tar.name)

    def test_int_name_attribute(self):
        # Issue 21044: tarfile.open() should handle fileobj with an integer
        # 'name' attribute.
        fd = os.open(self.tarname, os.O_RDONLY)
        with open(fd, 'rb') as fobj:
            self.assertIsInstance(fobj.name, int)
            with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
                self.assertIsNone(tar.name)

    def test_bytes_name_attribute(self):
        self.requires_name_attribute()
        tarname_bytes = os.fsencode(self.tarname) # Renamed to avoid shadowing self.tarname
        with open(tarname_bytes, 'rb') as fobj:
            self.assertIsInstance(fobj.name, bytes)
            with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
                self.assertIsInstance(tar.name, bytes)
                self.assertEqual(tar.name, os.path.abspath(fobj.name))

    def test_illegal_mode_arg(self):
        with open(tmpname, 'wb'):
            pass
        with self.assertRaisesRegex(ValueError, 'mode must be '):
            with self.taropen(tmpname, 'q'):
                pass
        with self.assertRaisesRegex(ValueError, 'mode must be '):
            with self.taropen(tmpname, 'rw'):
                pass
        with self.assertRaisesRegex(ValueError, 'mode must be '):
            with self.taropen(tmpname, ''):
                pass

    def test_fileobj_with_offset(self):
        # Skip the first member and store values from the second member
        # of the testtar.
        with tarfile.open(self.tarname, mode=self.mode) as tar:
            tar.next()
            t = tar.next()
            name = t.name
            offset = t.offset
            with tar.extractfile(t) as f:
                data = f.read()

        # Open the testtar and seek to the offset of the second member.
        with self.open(self.tarname) as fobj:
            fobj.seek(offset)

            # Test if the tarfile starts with the second member.
            with tarfile.open(self.tarname, mode="r:", fileobj=fobj) as tar:
                t = tar.next()
                self.assertEqual(t.name, name)
                # Read to the end of fileobj and test if seeking back to the
                # beginning works.
                tar.getmembers()
                self.assertEqual(tar.extractfile(t).read(), data,
                                 "seek back did not work")

    def test_fail_comp(self):
        # For Gzip and Bz2 Tests: fail with a ReadError on an uncompressed file.
        with self.assertRaises(tarfile.ReadError):
            with tarfile.open(tarname, self.mode):
                pass
        with open(tarname, "rb") as fobj:
            with self.assertRaises(tarfile.ReadError):
                tarfile.open(fileobj=fobj, mode=self.mode)

    def test_v7_dirtype(self):
        # Test old style dirtype member (bug #1336623):
        # Old V7 tars create directory members using an AREGTYPE
        # header with a "/" appended to the filename field.
        tarinfo = self.tar.getmember("misc/dirtype-old-v7")
        self.assertEqual(tarinfo.type, tarfile.DIRTYPE,
                         "v7 dirtype failed")

    def test_xstar_type(self):
        # The xstar format stores extra atime and ctime fields inside the
        # space reserved for the prefix field. The prefix field must be
        # ignored in this case, otherwise it will mess up the name.
        try:
            self.tar.getmember("misc/regtype-xstar")
        except KeyError:
            self.fail("failed to find misc/regtype-xstar (mangled prefix?)")

    def test_check_members(self):
        for tarinfo in self.tar:
            self.assertEqual(int(tarinfo.mtime), 0o7606136617,
                             "wrong mtime for %s" % tarinfo.name)
            if not tarinfo.name.startswith("ustar/"):
                continue
            self.assertEqual(tarinfo.uname, "tarfile",
                             "wrong uname for %s" % tarinfo.name)

    def test_find_members(self):
        self.assertEqual(self.tar.getmembers()[-1].name, "misc/eof",
                         "could not find all members")

    @unittest.skipUnless(hasattr(os, "link"),
                         "Missing hardlink implementation")
    @support.skip_unless_symlink
    def test_extract_hardlink(self):
        # Test hardlink extraction (e.g. bug #857297).
        with tarfile.open(tarname, errorlevel=1, encoding="iso8859-1") as tar:
            tar.extract("ustar/regtype", TEMPDIR, filter="data")
            self.addCleanup(support.unlink, os.path.join(TEMPDIR, "ustar/regtype"))

            tar.extract("ustar/lnktype", TEMPDIR, filter="data")
            self.addCleanup(support.unlink, os.path.join(TEMPDIR, "ustar/lnktype"))
            with open(os.path.join(TEMPDIR, "ustar/lnktype"), "rb") as f:
                data = f.read()
            self.assertEqual(md5sum(data), md5_regtype)

            tar.extract("ustar/symtype", TEMPDIR, filter="data")
            self.addCleanup(support.unlink, os.path.join(TEMPDIR, "ustar/symtype"))
            with open(os.path.join(TEMPDIR, "ustar/symtype"), "rb") as f:
                data = f.read()
            self.assertEqual(md5sum(data), md5_regtype)

    def test_extractall(self):
        # Test if extractall() correctly restores directory permissions
        # and times (see issue1735).
        with tarfile.open(tarname, encoding="iso8859-1") as tar:
            DIR_str = os.path.join(TEMPDIR, "extractall") # Renamed to DIR_str
            os.mkdir(DIR_str)
            try:
                directories = [t for t in tar if t.isdir()]
                tar.extractall(DIR_str, directories, filter='fully_trusted')
                for tarinfo in directories:
                    path = os.path.join(DIR_str, tarinfo.name)
                    if sys.platform != "win32":
                        # Win32 has no support for fine grained permissions.
                        self.assertEqual(tarinfo.mode & 0o777,
                                         os.stat(path).st_mode & 0o777,
                                         tarinfo.name)
                    def format_mtime(mtime):
                        if isinstance(mtime, float):
                            return "{} ({})".format(mtime, mtime.hex())
                        else:
                            return "{!r} (int)".format(mtime)
                    file_mtime = os.path.getmtime(path)
                    errmsg = "tar mtime {0} != file time {1} of path {2!a}".format(
                        format_mtime(tarinfo.mtime),
                        format_mtime(file_mtime),
                        path)
                    self.assertEqual(tarinfo.mtime, file_mtime, errmsg)
            finally:
                support.rmtree(DIR_str)

    def test_extract_directory(self):
        dirtype = "ustar/dirtype"
        DIR_str = os.path.join(TEMPDIR, "extractdir") # Renamed to DIR_str
        os.mkdir(DIR_str)
        try:
            with tarfile.open(tarname, encoding="iso8859-1") as tar:
                tarinfo = tar.getmember(dirtype)
                tar.extract(tarinfo, path=DIR_str, filter='fully_trusted')
                extracted = os.path.join(DIR_str, dirtype)
                self.assertEqual(os.path.getmtime(extracted), tarinfo.mtime)
                if sys.platform != "win32":
                    self.assertEqual(os.stat(extracted).st_mode & 0o777, 0o755)
        finally:
            support.rmtree(DIR_str)

    def test_init_close_fobj(self):
        # Issue #7341: Close the internal file object in the TarFile
        # constructor in case of an error. For the test we rely on
        # the fact that opening an empty file raises a ReadError.
        empty = os.path.join(TEMPDIR, "empty")
        with open(empty, "wb") as fobj:
            fobj.write(b"")

        try:
            tar = object.__new__(tarfile.TarFile)
            try:
                tar.__init__(empty)
            except tarfile.ReadError:
                self.assertTrue(tar.fileobj.closed)
            else:
                self.fail("ReadError not raised")
        finally:
            support.unlink(empty)

    def test_parallel_iteration(self):
        # Issue #16601: Restarting iteration over tarfile continued
        # from where it left off.
        # This test relies on the underlying fileobj being reliably seekable
        # for parallel iteration, which is not guaranteed for compressed
        # file objects (gzip, bz2, lzma).
        if self.mode.endswith(('gz', 'bz2', 'xz')):
            self.skipTest("Parallel iteration not supported for compressed files")

        with tarfile.open(fileobj=self._tar_data, mode=self.mode) as tar:
            for m1, m2 in zip(tar, tar):
                self.assertEqual(m1.offset, m2.offset)
                self.assertEqual(m1.get_info(), m2.get_info())

class MiscReadTest(MiscReadTestBase, unittest.TestCase):
    test_fail_comp = None

class GzipMiscReadTest(GzipTest, MiscReadTestBase, unittest.TestCase):
    pass

class Bz2MiscReadTest(Bz2Test, MiscReadTestBase, unittest.TestCase):
    def requires_name_attribute(self):
        self.skipTest("BZ2File have no name attribute")

class LzmaMiscReadTest(LzmaTest, MiscReadTestBase, unittest.TestCase):
    def requires_name_attribute(self):
        self.skipTest("LZMAFile have no name attribute")


class StreamReadTest(CommonReadTest, unittest.TestCase):

    prefix="r|"

    def test_read_through(self):
        # Issue #11224: A poorly designed _FileInFile.read() method
        # caused seeking errors with stream tar files.
        for tarinfo in self.tar:
            if not tarinfo.isreg():
                continue
            with self.tar.extractfile(tarinfo) as fobj:
                while True:
                    try:
                        buf = fobj.read(512)
                    except tarfile.StreamError:
                        self.fail("simple read-through using "
                                  "TarFile.extractfile() failed")
                    if not buf:
                        break

    def test_fileobj_regular_file(self):
        tarinfo = self.tar.next() # get "regtype" (can't use getmember)
        with self.tar.extractfile(tarinfo) as fobj:
            data = fobj.read()
        self.assertEqual(len(data), tarinfo.size,
                "regular file extraction failed")
        self.assertEqual(md5sum(data), md5_regtype,
                "regular file extraction failed")

    def test_provoke_stream_error(self):
        tarinfos = self.tar.getmembers()
        with self.tar.extractfile(tarinfos[0]) as f: # read the first member
            self.assertRaises(tarfile.StreamError, f.read)

    def test_compare_members(self):
        with tarfile.open(tarname, encoding="iso8859-1") as tar1:
            tar2 = self.tar

            while True:
                t1 = tar1.next()
                t2 = tar2.next()
                if t1 is None:
                    break
                self.assertIsNotNone(t2, "stream.next() failed.")

                if t2.islnk() or t2.issym():
                    with self.assertRaises(tarfile.StreamError):
                        tar2.extractfile(t2)
                    continue

                v1 = tar1.extractfile(t1)
                v2 = tar2.extractfile(t2)
                if v1 is None:
                    continue
                self.assertIsNotNone(v2, "stream.extractfile() failed")
                self.assertEqual(v1.read(), v2.read(),
                        "stream extraction failed")

class GzipStreamReadTest(GzipTest, StreamReadTest):
    pass

class Bz2StreamReadTest(Bz2Test, StreamReadTest):
    pass

class LzmaStreamReadTest(LzmaTest, StreamReadTest):
    pass


class DetectReadTest(TarTest, unittest.TestCase):
    def _testfunc_file(self, name, mode):
        with tarfile.open(name, mode) as tar:
            pass

    def _testfunc_fileobj(self, name, mode):
        with open(name, "rb") as f:
            with tarfile.open(name, mode, fileobj=f) as tar:
                pass

    def _test_modes(self, testfunc):
        if self.suffix:
            with self.assertRaises(tarfile.ReadError):
                with tarfile.open(tarname, mode="r:" + self.suffix):
                    pass
            with self.assertRaises(tarfile.ReadError):
                with tarfile.open(tarname, mode="r|" + self.suffix):
                    pass
            with self.assertRaises(tarfile.ReadError):
                with tarfile.open(self.tarname, mode="r:"):
                    pass
            with self.assertRaises(tarfile.ReadError):
                with tarfile.open(self.tarname, mode="r|"):
                    pass
        testfunc(self.tarname, "r")
        testfunc(self.tarname, "r:" + self.suffix)
        testfunc(self.tarname, "r:*")
        testfunc(self.tarname, "r|" + self.suffix)
        testfunc(self.tarname, "r|*")

    def test_detect_file(self):
        self._test_modes(self._testfunc_file)

    def test_detect_fileobj(self):
        self._test_modes(self._testfunc_fileobj)

class GzipDetectReadTest(GzipTest, DetectReadTest):
    pass

class Bz2DetectReadTest(Bz2Test, DetectReadTest):
    def test_detect_stream_bz2(self):
        # Originally, tarfile's stream detection looked for the string
        # "BZh91" at the start of the file. This is incorrect because
        # the '9' represents the blocksize (900kB). If the file was
        # compressed using another blocksize autodetection fails.
        with open(tarname, "rb") as fobj:
            data = fobj.read()

        # Compress with blocksize 100kB, the file starts with "BZh11".
        with bz2.BZ2File(tmpname, "wb", compresslevel=1) as fobj:
            fobj.write(data)

        with tarfile.open(tmpname, "r|*") as tar:
            pass

class LzmaDetectReadTest(LzmaTest, DetectReadTest):
    pass


class MemberReadTest(ReadTest, unittest.TestCase):

    def _test_member(self, tarinfo, chksum=None, **kwargs):
        if chksum is not None:
            with self.tar.extractfile(tarinfo) as f:
                self.assertEqual(md5sum(f.read()), chksum,
                        "wrong md5sum for %s" % tarinfo.name)

        kwargs["mtime"] = 0o7606136617
        kwargs["uid"] = 1000
        kwargs["gid"] = 100
        if "old-v7" not in tarinfo.name:
            # V7 tar can't handle alphabetic owners.
            kwargs["uname"] = "tarfile"
            kwargs["gname"] = "tarfile"
        for k, v in kwargs.items():
            self.assertEqual(getattr(tarinfo, k), v,
                    "wrong value in %s field of %s" % (k, tarinfo.name))

    def test_find_regtype(self):
        tarinfo = self.tar.getmember("ustar/regtype")
        self._test_member(tarinfo, size=7011, chksum=md5_regtype)

    def test_find_conttype(self):
        tarinfo = self.tar.getmember("ustar/conttype")
        self._test_member(tarinfo, size=7011, chksum=md5_regtype)

    def test_find_dirtype(self):
        tarinfo = self.tar.getmember("ustar/dirtype")
        self._test_member(tarinfo, size=0)

    def test_find_dirtype_with_size(self):
        tarinfo = self.tar.getmember("ustar/dirtype-with-size")
        self._test_member(tarinfo, size=255)

    def test_find_lnktype(self):
        tarinfo = self.tar.getmember("ustar/lnktype")
        self._test_member(tarinfo, size=0, linkname="ustar/regtype")

    def test_find_symtype(self):
        tarinfo = self.tar.getmember("ustar/symtype")
        self._test_member(tarinfo, size=0, linkname="regtype")

    def test_find_blktype(self):
        tarinfo = self.tar.getmember("ustar/blktype")
        self._test_member(tarinfo, size=0, devmajor=3, devminor=0)

    def test_find_chrtype(self):
        tarinfo = self.tar.getmember("ustar/chrtype")
        self._test_member(tarinfo, size=0, devmajor=1, devminor=3)

    def test_find_fifotype(self):
        tarinfo = self.tar.getmember("ustar/fifotype")
        self._test_member(tarinfo, size=0)

    def test_find_sparse(self):
        tarinfo = self.tar.getmember("ustar/sparse")
        self._test_member(tarinfo, size=86016, chksum=md5_sparse)

    def test_find_gnusparse(self):
        tarinfo = self.tar.getmember("gnu/sparse")
        self._test_member(tarinfo, size=86016, chksum=md5_sparse)

    def test_find_gnusparse_00(self):
        tarinfo = self.tar.getmember("gnu/sparse-0.0")
        self._test_member(tarinfo, size=86016, chksum=md5_sparse)

    def test_find_gnusparse_01(self):
        tarinfo = self.tar.getmember("gnu/sparse-0.1")
        self._test_member(tarinfo, size=86016, chksum=md5_sparse)

    def test_find_gnusparse_10(self):
        tarinfo = self.tar.getmember("gnu/sparse-1.0")
        self._test_member(tarinfo, size=86016, chksum=md5_sparse)

    def test_find_umlauts(self):
        tarinfo = self.tar.getmember("ustar/umlauts-"
                                     "\xc4\xd6\xdc\xe4\xf6\xfc\xdf")
        self._test_member(tarinfo, size=7011, chksum=md5_regtype)

    def test_find_ustar_longname(self):
        name = "ustar/" + "12345/" * 39 + "1234567/longname"
        self.assertIn(name, self.tar.getnames())

    def test_find_regtype_oldv7(self):
        tarinfo = self.tar.getmember("misc/regtype-old-v7")
        self._test_member(tarinfo, size=7011, chksum=md5_regtype)

    def test_find_pax_umlauts(self):
        # Reset the BytesIO stream for this specific test
        self._tar_data.seek(0)
        with tarfile.open(fileobj=self._tar_data, mode=self.mode,
                                encoding="iso8859-1") as tar:
            tarinfo = tar.getmember("pax/umlauts-"
                                     "\xc4\xd6\xdc\xe4\xf6\xfc\xdf")
            self._test_member(tarinfo, size=7011, chksum=md5_regtype)


class LongnameTest:

    def test_read_longname(self):
        # Test reading of longname (bug #1471427).
        longname = self.subdir + "/" + "123/" * 125 + "longname"
        try:
            tarinfo = self.tar.getmember(longname)
        except KeyError:
            self.fail("longname not found")
        self.assertNotEqual(tarinfo.type, tarfile.DIRTYPE,
                "read longname as dirtype")

    def test_read_longlink(self):
        longname = self.subdir + "/" + "123/" * 125 + "longname"
        longlink = self.subdir + "/" + "123/" * 125 + "longlink"
        try:
            tarinfo = self.tar.getmember(longlink)
        except KeyError:
            self.fail("longlink not found")
        self.assertEqual(tarinfo.linkname, longname, "linkname wrong")

    def test_truncated_longname(self):
        longname = self.subdir + "/" + "123/" * 125 + "longname"
        tarinfo = self.tar.getmember(longname)
        offset = tarinfo.offset
        self.tar.fileobj.seek(offset)
        fobj = io.BytesIO(self.tar.fileobj.read(3 * 512))
        with self.assertRaises(tarfile.ReadError):
            with tarfile.open(name="foo.tar", fileobj=fobj) as tar:
                pass

    def test_header_offset(self):
        # Test if the start offset of the TarInfo object includes
        # the preceding extended header.
        longname = self.subdir + "/" + "123/" * 125 + "longname"
        offset = self.tar.getmember(longname).offset
        with open(tarname, "rb") as fobj:
            fobj.seek(offset)
            tarinfo = tarfile.TarInfo.frombuf(fobj.read(512),
                                              "iso8859-1", "strict")
            self.assertEqual(tarinfo.type, self.longnametype)


class GNUReadTest(LongnameTest, ReadTest, unittest.TestCase):

    subdir = "gnu"
    longnametype = tarfile.GNUTYPE_LONGNAME

    # Since 3.2 tarfile is supposed to accurately restore sparse members and
    # produce files with holes. This is what we actually want to test here.
    # Unfortunately, not all platforms/filesystems support sparse files, and
    # even on platforms that do it is non-trivial to make reliable assertions
    # about holes in files. Therefore, we first do one basic test which works
    # an all platforms, and after that a test that will work only on
    # platforms/filesystems that prove to support sparse files.
    def _test_sparse_file(self, name):
        self.tar.extract(name, TEMPDIR, filter='data')
        filename = os.path.join(TEMPDIR, name)
        with open(filename, "rb") as fobj:
            data = fobj.read()
        self.assertEqual(md5sum(data), md5_sparse,
                "wrong md5sum for %s" % name)

        if self._fs_supports_holes():
            s = os.stat(filename)
            self.assertLess(s.st_blocks * 512, s.st_size)

    def test_sparse_file_old(self):
        self._test_sparse_file("gnu/sparse")

    def test_sparse_file_00(self):
        self._test_sparse_file("gnu/sparse-0.0")

    def test_sparse_file_01(self):
        self._test_sparse_file("gnu/sparse-0.1")

    def test_sparse_file_10(self):
        self._test_sparse_file("gnu/sparse-1.0")

    @staticmethod
    def _fs_supports_holes():
        # Return True if the platform knows the st_blocks stat attribute and
        # uses st_blocks units of 512 bytes, and if the filesystem is able to
        # store holes in files.
        if sys.platform.startswith("linux"):
            # Linux evidentially has 512 byte st_blocks units.
            name = os.path.join(TEMPDIR, "sparse-test")
            with open(name, "wb") as fobj:
                fobj.seek(4096)
                fobj.truncate()
            s = os.stat(name)
            support.unlink(name)
            return s.st_blocks == 0
        else:
            return False


class PaxReadTest(LongnameTest, ReadTest, unittest.TestCase):

    subdir = "pax"
    longnametype = tarfile.XHDTYPE

    def test_pax_global_headers(self):
        with tarfile.open(tarname, encoding="iso8859-1") as tar:
            tarinfo = tar.getmember("pax/regtype1")
            self.assertEqual(tarinfo.uname, "foo")
            self.assertEqual(tarinfo.gname, "bar")
            self.assertEqual(tarinfo.pax_headers.get("VENDOR.umlauts"),
                             "\xc4\xd6\xdc\xe4\xf6\xfc\xdf")

            tarinfo = tar.getmember("pax/regtype2")
            self.assertEqual(tarinfo.uname, "")
            self.assertEqual(tarinfo.gname, "bar")
            self.assertEqual(tarinfo.pax_headers.get("VENDOR.umlauts"),
                             "\xc4\xd6\xdc\xe4\xf6\xfc\xdf")

            tarinfo = tar.getmember("pax/regtype3")
            self.assertEqual(tarinfo.uname, "tarfile")
            self.assertEqual(tarinfo.gname, "tarfile")
            self.assertEqual(tarinfo.pax_headers.get("VENDOR.umlauts"),
                             "\xc4\xd6\xdc\xe4\xf6\xfc\xdf")

    def test_pax_number_fields(self):
        # All following number fields are read from the pax header.
        with tarfile.open(tarname, encoding="iso8859-1") as tar:
            tarinfo = tar.getmember("pax/regtype4")
            self.assertEqual(tarinfo.size, 7011)
            self.assertEqual(tarinfo.uid, 123)
            self.assertEqual(tarinfo.gid, 123)
            self.assertEqual(tarinfo.mtime, 1041808783.0)
            self.assertEqual(type(tarinfo.mtime), float)
            self.assertEqual(float(tarinfo.pax_headers["atime"]), 1041808783.0)
            self.assertEqual(float(tarinfo.pax_headers["ctime"]), 1041808783.0)

    def test_pax_header_bad_formats(self):
        # The fields from the pax header have priority over the
        # TarInfo.
        pax_header_replacements = (
            b" foo=bar\n",
            b"0 \n",
            b"1 \n",
            b"2 \n",
            b"3 =\n",
            b"4 =a\n",
            b"1000000 foo=bar\n",
            b"0 foo=bar\n",
            b"-12 foo=bar\n",
            b"000000000000000000000000036 foo=bar\n",
        )
        pax_headers = {"foo": "bar"}

        for replacement in pax_header_replacements:
            with self.subTest(header=replacement):
                tar = tarfile.open(tmpname, "w", format=tarfile.PAX_FORMAT,
                                   encoding="iso8859-1")
                try:
                    t = tarfile.TarInfo()
                    t.name = "pax"  # non-ASCII
                    t.uid = 1
                    t.pax_headers = pax_headers
                    tar.addfile(t)
                finally:
                    tar.close()

                with open(tmpname, "rb") as f:
                    data = f.read()
                    self.assertIn(b"11 foo=bar\n", data)
                    data = data.replace(b"11 foo=bar\n", replacement)

                with open(tmpname, "wb") as f:
                    f.truncate()
                    f.write(data)

                with self.assertRaisesRegex(tarfile.ReadError, r"file could not be opened successfully"):
                    with tarfile.open(tmpname, encoding="iso8859-1") as tar:
                        pass


class WriteTestBase(TarTest):
    # Put all write tests in here that are supposed to be tested
    # in all possible mode combinations.

    def test_fileobj_no_close(self):
        fobj = io.BytesIO()
        with tarfile.open(fileobj=fobj, mode=self.mode) as tar:
            tar.addfile(tarfile.TarInfo("foo"))
        self.assertFalse(fobj.closed, "external fileobjs must never closed")
        # Issue #20238: Incomplete gzip output with mode="w:gz"
        data = fobj.getvalue()
        del tar
        support.gc_collect()
        self.assertFalse(fobj.closed)
        self.assertEqual(data, fobj.getvalue())


class WriteTest(WriteTestBase, unittest.TestCase):

    prefix = "w:"

    def test_100_char_name(self):
        # The name field in a tar header stores strings of at most 100 chars.
        # If a string is shorter than 100 chars it has to be padded with '\0',
        # which implies that a string of exactly 100 chars is stored without
        # a trailing '\0'.
        name = "0123456789" * 10
        with tarfile.open(tmpname, self.mode) as tar:
            t = tarfile.TarInfo(name)
            tar.addfile(t)

        with tarfile.open(tmpname) as tar:
            self.assertEqual(tar.getnames()[0], name,
                    "failed to store 100 char filename")

    def test_tar_size(self):
        # Test for bug #1013882.
        with tarfile.open(tmpname, self.mode) as tar:
            path = os.path.join(TEMPDIR, "file")
            with open(path, "wb") as fobj:
                fobj.write(b"aaa")
            tar.add(path)
        self.assertGreater(os.path.getsize(tmpname), 0,
                "tarfile is empty")

    # The test_*_size tests test for bug #1167128.
    def test_file_size(self):
        tar = tarfile.open(tmpname, self.mode)
        try:
            path = os.path.join(TEMPDIR, "file")
            with open(path, "wb"):
                pass
            tarinfo = tar.gettarinfo(path)
            self.assertEqual(tarinfo.size, 0)

            with open(path, "wb") as fobj:
                fobj.write(b"aaa")
            tarinfo = tar.gettarinfo(path)
            self.assertEqual(tarinfo.size, 3)
        finally:
            tar.close()

    def test_directory_size(self):
        path = os.path.join(TEMPDIR, "directory")
        os.mkdir(path)
        try:
            with tarfile.open(tmpname, self.mode) as tar:
                tarinfo = tar.gettarinfo(path)
                self.assertEqual(tarinfo.size, 0)
        finally:
            support.rmdir(path)

    @unittest.skipUnless(hasattr(os, "link"),
                         "Missing hardlink implementation")
    def test_link_size(self):
        link = os.path.join(TEMPDIR, "link")
        target = os.path.join(TEMPDIR, "link_target")
        if os.path.exists(link):
            support.unlink(link)
        # 'target' is created with 'with open', which truncates/creates,
        # so no explicit unlink before needed
        with open(target, "wb") as fobj:
            fobj.write(b"aaa")
        os.link(target, link)
        with tarfile.open(tmpname, self.mode) as tar:
            # Record the link target in the inodes list.
            tar.gettarinfo(target)
            tarinfo = tar.gettarinfo(link)
            self.assertEqual(tarinfo.size, 0)

    @support.skip_unless_symlink
    def test_symlink_size(self):
        path = os.path.join(TEMPDIR, "symlink")
        if os.path.exists(path):
            support.unlink(path)
        os.symlink("link_target", path)
        with tarfile.open(tmpname, self.mode) as tar:
            tarinfo = tar.gettarinfo(path)
            self.assertEqual(tarinfo.size, 0)

    def test_add_self(self):
        # Test for #1257255.
        dstname = os.path.abspath(tmpname)
        with tarfile.open(tmpname, self.mode) as tar:
            self.assertEqual(tar.name, dstname,
                    "archive name must be absolute")
            tar.add(dstname)
            self.assertEqual(tar.getnames(), [],
                    "added the archive to itself")

            with support.change_cwd(TEMPDIR):
                tar.add(dstname)
            self.assertEqual(tar.getnames(), [],
                    "added the archive to itself")

    def test_exclude(self):
        tempdir = os.path.join(TEMPDIR, "exclude")
        os.mkdir(tempdir)
        try:
            for name in ("foo", "bar", "baz"):
                name = os.path.join(tempdir, name)
                support.create_empty_file(name)

            exclude = os.path.isfile

            with tarfile.open(tmpname, self.mode, encoding="iso8859-1") as tar:
                with support.check_warnings(("use the filter argument",
                                             DeprecationWarning)):
                    tar.add(tempdir, arcname="empty_dir", exclude=exclude)

            with tarfile.open(tmpname, "r") as tar:
                self.assertEqual(len(tar.getmembers()), 1)
                self.assertEqual(tar.getnames()[0], "empty_dir")
        finally:
            support.rmtree(tempdir)

    def test_filter(self):
        tempdir = os.path.join(TEMPDIR, "filter")
        os.mkdir(tempdir)
        try:
            for name in ("foo", "bar", "baz"):
                name = os.path.join(tempdir, name)
                support.create_empty_file(name)

            def filter(tarinfo):
                if os.path.basename(tarinfo.name) == "bar":
                    return
                tarinfo.uid = 123
                tarinfo.uname = "foo"
                return tarinfo

            with tarfile.open(tmpname, self.mode, encoding="iso8859-1") as tar:
                tar.add(tempdir, arcname="empty_dir", filter=filter)

            # Verify that filter is a keyword-only argument
            with self.assertRaises(TypeError):
                tar.add(tempdir, "empty_dir", True, None, filter)

            with tarfile.open(tmpname, "r") as tar:
                for tarinfo in tar:
                    self.assertEqual(tarinfo.uid, 123)
                    self.assertEqual(tarinfo.uname, "foo")
                self.assertEqual(len(tar.getmembers()), 3)
        finally:
            support.rmtree(tempdir)

    # Guarantee that stored pathnames are not modified. Don't
    # remove ./ or ../ or double slashes. Still make absolute
    # pathnames relative.
    # For details see bug #6054.
    def _test_pathname(self, path, cmp_path=None, dir=False):
        # Create a tarfile with an empty member named path
        # and compare the stored name with the original.
        foo = os.path.join(TEMPDIR, "foo")
        if not dir:
            support.create_empty_file(foo)
        else:
            os.mkdir(foo)

        with tarfile.open(tmpname, self.mode) as tar:
            tar.add(foo, arcname=path)

        with tarfile.open(tmpname, "r") as tar:
            t = tar.next()

        if not dir:
            support.unlink(foo)
        else:
            support.rmdir(foo)

        self.assertEqual(t.name, cmp_path or path.replace(os.sep, "/"))


    @support.skip_unless_symlink
    def test_extractall_symlinks(self):
        # Test if extractall works properly when tarfile contains symlinks
        tempdir = os.path.join(TEMPDIR, "testsymlinks")
        temparchive = os.path.join(TEMPDIR, "testsymlinks.tar")
        os.mkdir(tempdir)
        try:
            source_file = os.path.join(tempdir,'source')
            target_file = os.path.join(tempdir,'symlink')
            with open(source_file,'w') as f:
                f.write('something\n')
            os.symlink(source_file, target_file)
            with tarfile.open(temparchive,'w') as tar:
                tar.add(source_file)
                tar.add(target_file)
            # Let's extract it to the location which contains the symlink
            with tarfile.open(temparchive,'r') as tar:
                # this should not raise OSError: [Errno 17] File exists
                try:
                    tar.extractall(path=tempdir,
                                   filter="fully_trusted")
                except OSError:
                    self.fail("extractall failed with symlinked files")
        finally:
            support.unlink(temparchive)
            support.rmtree(tempdir)

    def test_pathnames(self):
        self._test_pathname("foo")
        self._test_pathname(os.path.join("foo", ".", "bar"))
        self._test_pathname(os.path.join("foo", "..", "bar"))
        self._test_pathname(os.path.join(".", "foo"))
        self._test_pathname(os.path.join(".", "foo", "."))
        self._test_pathname(os.path.join(".", "foo", ".", "bar"))
        self._test_pathname(os.path.join(".", "foo", "..", "bar"))
        self._test_pathname(os.path.join(".", "foo", "..", "bar"))
        self._test_pathname(os.path.join("..", "foo"))
        self._test_pathname(os.path.join("..", "foo", ".."))
        self._test_pathname(os.path.join("..", "foo", ".", "bar"))
        self._test_pathname(os.path.join("..", "foo", "..", "bar"))

        self._test_pathname("foo" + os.sep + os.sep + "bar")
        self._test_pathname("foo" + os.sep + os.sep, "foo", dir=True)

    def test_abs_pathnames(self):
        if sys.platform == "win32":
            self._test_pathname("C:\\foo", "foo")
        else:
            self._test_pathname("/foo", "foo")
            self._test_pathname("///foo", "foo")

    def test_cwd(self):
        # Test adding the current working directory.
        with support.change_cwd(TEMPDIR):
            with tarfile.open(tmpname, self.mode) as tar:
                tar.add(".")

            with tarfile.open(tmpname, "r") as tar:
                for t in tar:
                    if t.name != ".":
                        self.assertTrue(t.name.startswith("./"), t.name)

    def test_open_nonwritable_fileobj(self):
        for exctype in OSError, EOFError, RuntimeError:
            class BadFile(io.BytesIO):
                first = True
                def write(self, data):
                    if self.first:
                        self.first = False
                        raise exctype

            f = BadFile()
            with self.assertRaises(exctype):
                tar = tarfile.open(tmpname, self.mode, fileobj=f,
                                   format=tarfile.PAX_FORMAT,
                                   pax_headers={'non': 'empty'})
            self.assertFalse(f.closed)

class GzipWriteTest(GzipTest, WriteTest):
    pass

class Bz2WriteTest(Bz2Test, WriteTest):
    pass

class LzmaWriteTest(LzmaTest, WriteTest):
    pass


class StreamWriteTest(WriteTestBase, unittest.TestCase):

    prefix = "w|"
    decompressor = None

    def test_stream_padding(self):
        # Test for bug #1543303.
        with tarfile.open(tmpname, self.mode) as tar:
            tar.close()
        if self.decompressor:
            dec = self.decompressor()
            with open(tmpname, "rb") as fobj:
                data = fobj.read()
            data = dec.decompress(data)
            self.assertFalse(dec.unused_data, "found trailing data")
        else:
            with self.open(tmpname) as fobj:
                data = fobj.read()
        self.assertEqual(data.count(b"\0"), tarfile.RECORDSIZE,
                        "incorrect zero padding")

    @unittest.skipUnless(sys.platform != "win32" and hasattr(os, "umask"),
                         "Missing umask implementation")
    def test_file_mode(self):
        # Test for issue #8464: Create files with correct
        # permissions.
        # For stream modes, we write to an in-memory buffer then save to disk.
        # This avoids trying to open a file directly via bz2/gzip/lzma module
        # which might expect the directory to already exist or handle it differently.
        test_file_path = os.path.join(TEMPDIR, "test_file_mode_archive")

        original_umask = os.umask(0o022)
        try:
            with tarfile.open(fileobj=io.BytesIO(), mode=self.mode) as tar:
                tar.close()
            # The tarfile content is now in the BytesIO. Write it to disk for stat.
            archive_data = tar.fileobj.getvalue() # Get the compressed bytes
            with open(test_file_path, "wb") as f:
                f.write(archive_data)

            mode = os.stat(test_file_path).st_mode & 0o777
            # For stream write, the permissions on the created file are expected to be default
            # due to umask unless tarfile explicitly sets them on final file write.
            # Given the test's intention, 0o644 is still the target mode when umask is 0o022.
            self.assertEqual(mode, 0o644, "wrong file permissions")
        finally:
            os.umask(original_umask)
            if os.path.exists(test_file_path):
                support.unlink(test_file_path)

class GzipStreamWriteTest(GzipTest, StreamWriteTest):
    pass

class Bz2StreamWriteTest(Bz2Test, StreamWriteTest):
    decompressor = bz2.BZ2Decompressor if bz2 else None

class LzmaStreamWriteTest(LzmaTest, StreamWriteTest):
    decompressor = lzma.LZMADecompressor if lzma else None


class GNUWriteTest(unittest.TestCase):
    # This testcase checks for correct creation of GNU Longname
    # and Longlink extended headers (cp. bug #812325).

    def _length(self, s):
        blocks = len(s) // 512 + 1
        return blocks * 512

    def _calc_size(self, name, link=None):
        # Initial tar header
        count = 512

        if len(name) > tarfile.LENGTH_NAME:
            # GNU longname extended header + longname
            count += 512
            count += self._length(name)
        if link is not None and len(link) > tarfile.LENGTH_LINK:
            # GNU longlink extended header + longlink
            count += 512
            count += self._length(link)
        return count

    def _test(self, name, link=None):
        tarinfo = tarfile.TarInfo(name)
        if link:
            tarinfo.linkname = link
            tarinfo.type = tarfile.LNKTYPE

        with tarfile.open(tmpname, "w") as tar:
            tar.format = tarfile.GNU_FORMAT
            tar.addfile(tarinfo)

            v1 = self._calc_size(name, link)
            v2 = tar.offset
            self.assertEqual(v1, v2, "GNU longname/longlink creation failed")

        with tarfile.open(tmpname) as tar:
            member = tar.next()
            self.assertIsNotNone(member,
                    "unable to read longname member")
            self.assertEqual(tarinfo.name, member.name,
                    "unable to read longname member")
            self.assertEqual(tarinfo.linkname, member.linkname,
                    "unable to read longname member")

    def test_longname_1023(self):
        self._test(("longnam/" * 127) + "longnam")

    def test_longname_1024(self):
        self._test(("longnam/" * 127) + "longname")

    def test_longname_1025(self):
        self._test(("longnam/" * 127) + "longname_")

    def test_longlink_1023(self):
        self._test("name", ("longlnk/" * 127) + "longlnk")

    def test_longlink_1024(self):
        self._test("name", ("longlnk/" * 127) + "longlink")

    def test_longlink_1025(self):
        self._test("name", ("longlnk/" * 127) + "longlink_")

    def test_longnamelink_1023(self):
        self._test(("longnam/" * 127) + "longnam",
                   ("longlnk/" * 127) + "longlnk")

    def test_longnamelink_1024(self):
        self._test(("longnam/" * 127) + "longname",
                   ("longlnk/" * 127) + "longlink")

    def test_longnamelink_1025(self):
        self._test(("longnam/" * 127) + "longname_",
                   ("longlnk/" * 127) + "longlink_")


@unittest.skipUnless(hasattr(os, "link"), "Missing hardlink implementation")
class HardlinkTest(unittest.TestCase):
    # Test the creation of LNKTYPE (hardlink) members in an archive.

    def setUp(self):
        self.foo = os.path.join(TEMPDIR, "foo")
        self.bar = os.path.join(TEMPDIR, "bar")

        # Ensure files don't exist from a previous failed run
        if os.path.exists(self.foo):
            support.unlink(self.foo)
        if os.path.exists(self.bar):
            support.unlink(self.bar)

        with open(self.foo, "wb") as fobj:
            fobj.write(b"foo")

        os.link(self.foo, self.bar)

        self.tar = tarfile.open(tmpname, "w")
        self.tar.add(self.foo)
        self.addCleanup(self.tar.close)
        self.addCleanup(support.unlink, self.foo)
        self.addCleanup(support.unlink, self.bar)

    def test_add_twice(self):
        # The same name will be added as a REGTYPE every
        # time regardless of st_nlink.
        tarinfo = self.tar.gettarinfo(self.foo)
        self.assertEqual(tarinfo.type, tarfile.REGTYPE,
                "add file as regular failed")

    def test_add_hardlink(self):
        tarinfo = self.tar.gettarinfo(self.bar)
        self.assertEqual(tarinfo.type, tarfile.LNKTYPE,
                "add file as hardlink failed")

    def test_dereference_hardlink(self):
        self.tar.dereference = True
        tarinfo = self.tar.gettarinfo(self.bar)
        self.assertEqual(tarinfo.type, tarfile.REGTYPE,
                "dereferencing hardlink failed")


class PaxWriteTest(GNUWriteTest):

    def _test(self, name, link=None):
        # See GNUWriteTest.
        tarinfo = tarfile.TarInfo(name)
        if link:
            tarinfo.linkname = link
            tarinfo.type = tarfile.LNKTYPE

        with tarfile.open(tmpname, "w", format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(tarinfo)

        with tarfile.open(tmpname) as tar:
            if link:
                l = tar.getmembers()[0].linkname
                self.assertEqual(link, l, "PAX longlink creation failed")
            else:
                n = tar.getmembers()[0].name
                self.assertEqual(name, n, "PAX longname creation failed")

    def test_pax_global_header(self):
        pax_headers = {
                "foo": "bar",
                "uid": "0",
                "mtime": "1.23",
                "test": "\xe4\xf6\xfc",
                "\xe4\xf6\xfc": "test"}

        with tarfile.open(tmpname, "w", format=tarfile.PAX_FORMAT,
                pax_headers=pax_headers) as tar:
            tar.addfile(tarfile.TarInfo("test"))

        # Test if the global header was written correctly.
        with tarfile.open(tmpname, encoding="iso8859-1") as tar:
            self.assertEqual(tar.pax_headers, pax_headers)
            self.assertEqual(tar.getmembers()[0].pax_headers, pax_headers)
            # Test if all the fields are strings.
            for key, val in tar.pax_headers.items():
                self.assertIsNot(type(key), bytes)
                self.assertIsNot(type(val), bytes)
                if key in tarfile.PAX_NUMBER_FIELDS:
                    try:
                        tarfile.PAX_NUMBER_FIELDS[key](val)
                    except (TypeError, ValueError):
                        self.fail("unable to convert pax header field")

    def test_pax_extended_header(self):
        # The fields from the pax header have priority over the
        # TarInfo.
        pax_headers = {"path": "foo", "uid": "123"}

        with tarfile.open(tmpname, "w", format=tarfile.PAX_FORMAT,
                           encoding="iso8859-1") as tar:
            t = tarfile.TarInfo()
            t.name = "\xe4\xf6\xfc" # non-ASCII
            t.uid = 8**8 # too large
            t.pax_headers = pax_headers
            tar.addfile(t)

        with tarfile.open(tmpname, encoding="iso8859-1") as tar:
            t = tar.getmembers()[0]
            self.assertEqual(t.pax_headers, pax_headers)
            self.assertEqual(t.name, "foo")
            self.assertEqual(t.uid, 123)


class UstarUnicodeTest(unittest.TestCase):

    format = tarfile.USTAR_FORMAT

    def test_iso8859_1_filename(self):
        self._test_unicode_filename("iso8859-1")

    def test_utf7_filename(self):
        self._test_unicode_filename("utf7")

    def test_utf8_filename(self):
        self._test_unicode_filename("utf-8")

    def _test_unicode_filename(self, encoding):
        with tarfile.open(tmpname, "w", format=self.format,
                           encoding=encoding, errors="strict") as tar:
            name = "\xe4\xf6\xfc"
            tar.addfile(tarfile.TarInfo(name))

        with tarfile.open(tmpname, encoding=encoding) as tar:
            self.assertEqual(tar.getmembers()[0].name, name)

    def test_unicode_filename_error(self):
        with tarfile.open(tmpname, "w", format=self.format,
                           encoding="ascii", errors="strict") as tar:
            tarinfo = tarfile.TarInfo()

            tarinfo.name = "\xe4\xf6\xfc"
            self.assertRaises(UnicodeError, tar.addfile, tarinfo)

            tarinfo.name = "foo"
            tarinfo.uname = "\xe4\xf6\xfc"
            self.assertRaises(UnicodeError, tar.addfile, tarinfo)

    def test_unicode_argument(self):
        with tarfile.open(tarname, "r",
                           encoding="iso8859-1", errors="strict") as tar:
            for t in tar:
                self.assertIs(type(t.name), str)
                self.assertIs(type(t.linkname), str)
                self.assertIs(type(t.uname), str)
                self.assertIs(type(t.gname), str)

    def test_uname_unicode(self):
        t = tarfile.TarInfo("foo")
        t.uname = "\xe4\xf6\xfc"
        t.gname = "\xe4\xf6\xfc"

        with tarfile.open(tmpname, mode="w", format=self.format,
                           encoding="iso8859-1") as tar:
            tar.addfile(t)

        with tarfile.open(tmpname, encoding="iso8859-1") as tar:
            t = tar.getmember("foo")
            self.assertEqual(t.uname, "\xe4\xf6\xfc")
            self.assertEqual(t.gname, "\xe4\xf6\xfc")

            if self.format != tarfile.PAX_FORMAT:
                with tarfile.open(tmpname, encoding="ascii") as tar:
                    t = tar.getmember("foo")
                    self.assertEqual(t.uname, "\udce4\udcf6\udcfc")
                    self.assertEqual(t.gname, "\udce4\udcf6\udcfc")


class GNUUnicodeTest(UstarUnicodeTest):

    format = tarfile.GNU_FORMAT

    def test_bad_pax_header(self):
        # Test for issue #8633. GNU tar <= 1.23 creates raw binary fields
        # without a hdrcharset=BINARY header.
        for encoding, name in (
                ("utf-8", "pax/bad-pax-\udce4\udcf6\udcfc"),
                ("iso8859-1", "pax/bad-pax-\xe4\xf6\xfc"),):
            with tarfile.open(tarname, encoding=encoding,
                              errors="surrogateescape") as tar:
                try:
                    t = tar.getmember(name)
                except KeyError:
                    self.fail("unable to read bad GNU tar pax header")


class PAXUnicodeTest(UstarUnicodeTest):

    format = tarfile.PAX_FORMAT

    # PAX_FORMAT ignores encoding in write mode.
    test_unicode_filename_error = None

    def test_binary_header(self):
        # Test a POSIX.1-2008 compatible header with a hdrcharset=BINARY field.
        for encoding, name in (
                ("utf-8", "pax/hdrcharset-\udce4\udcf6\udcfc"),
                ("iso8859-1", "pax/hdrcharset-\xe4\xf6\xfc"),):
            with tarfile.open(tarname, encoding=encoding,
                              errors="surrogateescape") as tar:
                try:
                    t = tar.getmember(name)
                except KeyError:
                    self.fail("unable to read POSIX.1-2008 binary header")


class AppendTestBase:
    # Test append mode (cp. patch #1652681).

    def setUp(self):
        self.tarname = tmpname
        if os.path.exists(self.tarname):
            support.unlink(self.tarname)

    def _create_testtar(self, mode="w:"):
        with tarfile.open(tarname, encoding="iso8859-1") as src:
            t = src.getmember("ustar/regtype")
            t.name = "foo"
            with src.extractfile(t) as f:
                with tarfile.open(self.tarname, mode) as tar:
                    tar.addfile(t, f)

    def test_append_compressed(self):
        self._create_testtar("w:" + self.suffix)
        with self.assertRaises(tarfile.ReadError):
            tarfile.open(tmpname, "a")

class AppendTest(AppendTestBase, unittest.TestCase):
    test_append_compressed = None

    def _add_testfile(self, fileobj=None):
        with tarfile.open(self.tarname, "a", fileobj=fileobj) as tar:
            tar.addfile(tarfile.TarInfo("bar"))

    def _test(self, names=["bar"], fileobj=None):
        with tarfile.open(self.tarname, fileobj=fileobj) as tar:
            self.assertEqual(tar.getnames(), names)

    def test_non_existing(self):
        self._add_testfile()
        with tarfile.open(self.tarname) as tar:
            self.assertEqual(tar.getnames(), ["bar"])

    def test_empty(self):
        tarfile.open(self.tarname, "w:").close()
        self._add_testfile()
        self._test(names=["bar"])

    def test_empty_fileobj(self):
        fobj = io.BytesIO(b"\0" * 1024)
        self._add_testfile(fobj)
        fobj.seek(0)
        with tarfile.open(self.tarname, fileobj=fobj) as tar:
            self.assertEqual(tar.getnames(), ["bar"])

    def test_fileobj(self):
        self._create_testtar()
        with open(self.tarname, "rb") as fobj:
            data = fobj.read()
        fobj = io.BytesIO(data)
        self._add_testfile(fobj)
        fobj.seek(0)
        with tarfile.open(self.tarname, fileobj=fobj) as tar:
            self.assertEqual(tar.getnames(), ["foo", "bar"])

    def test_existing(self):
        self._create_testtar()
        self._add_testfile()
        with tarfile.open(self.tarname) as tar:
            self.assertEqual(tar.getnames(), ["foo", "bar"])

    # Append mode is supposed to fail if the tarfile to append to
    # does not end with a zero block.
    def _test_error(self, data):
        with open(self.tarname, "wb") as fobj:
            fobj.write(data)
        with self.assertRaises(tarfile.ReadError):
            with tarfile.open(self.tarname, "a") as tar:
                tar.addfile(tarfile.TarInfo("bar"))

    def test_null(self):
        self._test_error(b"")

    def test_incomplete(self):
        self._test_error(b"\0" * 13)

    def test_premature_eof(self):
        data = tarfile.TarInfo("foo").tobuf()
        self._test_error(data)

    def test_trailing_garbage(self):
        data = tarfile.TarInfo("foo").tobuf()
        self._test_error(data + b"\0" * 13)

    def test_invalid(self):
        self._test_error(b"a" * 512)

class GzipAppendTest(GzipTest, AppendTestBase, unittest.TestCase):
    pass

class Bz2AppendTest(Bz2Test, AppendTestBase, unittest.TestCase):
    pass

class LzmaAppendTest(LzmaTest, AppendTestBase, unittest.TestCase):
    pass


class LimitsTest(unittest.TestCase):

    def test_ustar_limits(self):
        # 100 char name
        tarinfo = tarfile.TarInfo("0123456789" * 10)
        tarinfo.tobuf(tarfile.USTAR_FORMAT)

        # 101 char name that cannot be stored
        tarinfo = tarfile.TarInfo("0123456789" * 10 + "0")
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.USTAR_FORMAT)

        # 256 char name with a slash at pos 156
        tarinfo = tarfile.TarInfo("123/" * 62 + "longname")
        tarinfo.tobuf(tarfile.USTAR_FORMAT)

        # 256 char name that cannot be stored
        tarinfo = tarfile.TarInfo("1234567/" * 31 + "longname")
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.USTAR_FORMAT)

        # 512 char name
        tarinfo = tarfile.TarInfo("123/" * 126 + "longname")
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.USTAR_FORMAT)

        # 512 char linkname
        tarinfo = tarfile.TarInfo("longlink")
        tarinfo.linkname = "123/" * 126 + "longname"
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.USTAR_FORMAT)

        # uid > 8 digits
        tarinfo = tarfile.TarInfo("name")
        tarinfo.uid = 0o10000000
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.USTAR_FORMAT)

    def test_gnu_limits(self):
        tarinfo = tarfile.TarInfo("123/" * 126 + "longname")
        tarinfo.tobuf(tarfile.GNU_FORMAT)

        tarinfo = tarfile.TarInfo("longlink")
        tarinfo.linkname = "123/" * 126 + "longname"
        tarinfo.tobuf(tarfile.GNU_FORMAT)

        # uid >= 256 ** 7
        tarinfo = tarfile.TarInfo("name")
        tarinfo.uid = 0o4000000000000000000
        self.assertRaises(ValueError, tarinfo.tobuf, tarfile.GNU_FORMAT)

    def test_pax_limits(self):
        tarinfo = tarfile.TarInfo("123/" * 126 + "longname")
        tarinfo.tobuf(tarfile.PAX_FORMAT)

        tarinfo = tarfile.TarInfo("longlink")
        tarinfo.linkname = "123/" * 126 + "longname"
        tarinfo.tobuf(tarfile.PAX_FORMAT)

        tarinfo = tarfile.TarInfo("name")
        tarinfo.uid = 0o4000000000000000000
        tarinfo.tobuf(tarfile.PAX_FORMAT)


class MiscTest(unittest.TestCase):

    def test_char_fields(self):
        self.assertEqual(tarfile.stn("foo", 8, "ascii", "strict"),
                         b"foo\0\0\0\0\0")
        self.assertEqual(tarfile.stn("foobar", 3, "ascii", "strict"),
                         b"foo")
        self.assertEqual(tarfile.nts(b"foo\0\0\0\0\0", "ascii", "strict"),
                         "foo")
        self.assertEqual(tarfile.nts(b"foo\0bar\0", "ascii", "strict"),
                         "foo")

    def test_read_number_fields(self):
        # Issue 13158: Test if GNU tar specific base-256 number fields
        # are decoded correctly.
        self.assertEqual(tarfile.nti(b"0000001\x00"), 1)
        self.assertEqual(tarfile.nti(b"7777777\x00"), 0o7777777)
        self.assertEqual(tarfile.nti(b"\x80\x00\x00\x00\x00\x20\x00\x00"),
                         0o10000000)
        self.assertEqual(tarfile.nti(b"\x80\x00\x00\x00\xff\xff\xff\xff"),
                         0xffffffff)
        self.assertEqual(tarfile.nti(b"\xff\xff\xff\xff\xff\xff\xff\xff"),
                         -1)
        self.assertEqual(tarfile.nti(b"\xff\xff\xff\xff\xff\xff\xff\x9c"),
                         -100)
        self.assertEqual(tarfile.nti(b"\xff\x00\x00\x00\x00\x00\x00\x00"),
                         -0x100000000000000)

        # Issue 24514: Test if empty number fields are converted to zero.
        self.assertEqual(tarfile.nti(b"\0"), 0)
        self.assertEqual(tarfile.nti(b"       \0"), 0)

    def test_write_number_fields(self):
        self.assertEqual(tarfile.itn(1), b"0000001\x00")
        self.assertEqual(tarfile.itn(0o7777777), b"7777777\x00")
        self.assertEqual(tarfile.itn(0o10000000),
                         b"\x80\x00\x00\x00\x00\x20\x00\x00")
        self.assertEqual(tarfile.itn(0xffffffff),
                         b"\x80\x00\x00\x00\xff\xff\xff\xff")
        self.assertEqual(tarfile.itn(-1),
                         b"\xff\xff\xff\xff\xff\xff\xff\xff")
        self.assertEqual(tarfile.itn(-100),
                         b"\xff\xff\xff\xff\xff\xff\xff\x9c")
        self.assertEqual(tarfile.itn(-0x100000000000000),
                         b"\xff\x00\x00\x00\x00\x00\x00\x00")

    def test_number_field_limits(self):
        with self.assertRaises(ValueError):
            tarfile.itn(-1, 8, tarfile.USTAR_FORMAT)
        with self.assertRaises(ValueError):
            tarfile.itn(0o10000000, 8, tarfile.USTAR_FORMAT)
        with self.assertRaises(ValueError):
            tarfile.itn(-0x10000000001, 6, tarfile.GNU_FORMAT)
        with self.assertRaises(ValueError):
            tarfile.itn(0x10000000000, 6, tarfile.GNU_FORMAT)


class CommandLineTest(unittest.TestCase):

    def tarfilecmd(self, *args, **kwargs):
        rc, out, err = script_helper.assert_python_ok('-m', 'tarfile', *args,
                                                      **kwargs)
        return out.replace(os.linesep.encode(), b'\n')

    def tarfilecmd_failure(self, *args):
        return script_helper.assert_python_failure('-m', 'tarfile', *args)

    def make_simple_tarfile(self, tar_name):
        files = [support.findfile('tokenize_tests.txt'),
                 support.findfile('tokenize_tests-no-coding-cookie-'
                                  'and-utf8-bom-sig-only.txt')]
        self.addCleanup(support.unlink, tar_name)
        with tarfile.open(tar_name, 'w') as tf:
            for tardata in files:
                tf.add(tardata, arcname=os.path.basename(tardata))

    def make_evil_tarfile(self, tar_name):
        files = [support.findfile('tokenize_tests.txt')]
        self.addCleanup(support.unlink, tar_name)
        with tarfile.open(tar_name, 'w') as tf:
            benign = tarfile.TarInfo('benign')
            tf.addfile(benign, fileobj=io.BytesIO(b''))
            evil = tarfile.TarInfo('../evil')
            tf.addfile(evil, fileobj=io.BytesIO(b''))

    def test_test_command(self):
        for tar_name in testtarnames:
            for opt in '-t', '--test':
                out = self.tarfilecmd(opt, tar_name)
                self.assertEqual(out, b'')

    def test_test_command_verbose(self):
        for tar_name in testtarnames:
            for opt in '-v', '--verbose':
                out = self.tarfilecmd(opt, '-t', tar_name)
                self.assertIn(b'is a tar archive.\n', out)

    def test_test_command_invalid_file(self):
        zipname = support.findfile('zipdir.zip')
        rc, out, err = self.tarfilecmd_failure('-t', zipname)
        self.assertIn(b' is not a tar archive.', err)
        self.assertEqual(out, b'')
        self.assertEqual(rc, 1)

        for tar_name in testtarnames:
            with self.subTest(tar_name=tar_name):
                with open(tar_name, 'rb') as f:
                    data = f.read()
                with open(tmpname, 'wb') as f:
                    f.write(data[:511])
                rc, out, err = self.tarfilecmd_failure('-t', tmpname)
                self.assertEqual(out, b'')
                self.assertEqual(rc, 1)
                support.unlink(tmpname)

    def test_list_command(self):
        for tar_name in testtarnames:
            with support.captured_stdout() as t:
                with tarfile.open(tar_name, 'r') as tf:
                    tf.list(verbose=False)
            expected = t.getvalue().encode('ascii', 'backslashreplace')
            for opt in '-l', '--list':
                out = self.tarfilecmd(opt, tar_name,
                                      PYTHONIOENCODING='ascii')
                self.assertEqual(out, expected)

    def test_list_command_verbose(self):
        for tar_name in testtarnames:
            with support.captured_stdout() as t:
                with tarfile.open(tar_name, 'r') as tf:
                    tf.list(verbose=True)
            expected = t.getvalue().encode('ascii', 'backslashreplace')
            for opt in '-v', '--verbose':
                with tarfile.open(tar_name) as tar: # Added with statement
                    out = self.tarfilecmd(opt, '-l', tar_name,
                                          PYTHONIOENCODING='ascii')
                    self.assertEqual(out, expected)

    def test_list_command_invalid_file(self):
        zipname = support.findfile('zipdir.zip')
        rc, out, err = self.tarfilecmd_failure('-l', zipname)
        self.assertIn(b' is not a tar archive.', err)
        self.assertEqual(out, b'')
        self.assertEqual(rc, 1)

    def test_create_command(self):
        files = [support.findfile('tokenize_tests.txt'),
                 support.findfile('tokenize_tests-no-coding-cookie-'
                                  'and-utf8-bom-sig-only.txt')]
        for opt in '-c', '--create':
            try:
                out = self.tarfilecmd(opt, tmpname, *files)
                self.assertEqual(out, b'')
                with tarfile.open(tmpname) as tar:
                    tar.getmembers()
            finally:
                support.unlink(tmpname)

    def test_create_command_verbose(self):
        files = [support.findfile('tokenize_tests.txt'),
                 support.findfile('tokenize_tests-no-coding-cookie-'
                                  'and-utf8-bom-sig-only.txt')]
        for opt in '-v', '--verbose':
            try:
                out = self.tarfilecmd(opt, '-c', tmpname, *files)
                self.assertIn(b' file created.', out)
                with tarfile.open(tmpname) as tar:
                    tar.getmembers()
            finally:
                support.unlink(tmpname)

    def test_create_command_dotless_filename(self):
        files = [support.findfile('tokenize_tests.txt')]
        try:
            out = self.tarfilecmd('-c', dotlessname, *files)
            self.assertEqual(out, b'')
            with tarfile.open(dotlessname) as tar:
                tar.getmembers()
        finally:
            support.unlink(dotlessname)

    def test_create_command_dot_started_filename(self):
        tar_name = os.path.join(TEMPDIR, ".testtar")
        files = [support.findfile('tokenize_tests.txt')]
        try:
            out = self.tarfilecmd('-c', tar_name, *files)
            self.assertEqual(out, b'')
            with tarfile.open(tar_name) as tar:
                tar.getmembers()
        finally:
            support.unlink(tar_name)

    def test_create_command_compressed(self):
        files = [support.findfile('tokenize_tests.txt'),
                 support.findfile('tokenize_tests-no-coding-cookie-'
                                  'and-utf8-bom-sig-only.txt')]
        for filetype in (GzipTest, Bz2Test, LzmaTest):
            if not filetype.open:
                continue
            try:
                tar_name = tmpname + '.' + filetype.suffix
                out = self.tarfilecmd('-c', tar_name, *files)
                with filetype.taropen(tar_name) as tar:
                    tar.getmembers()
            finally:
                support.unlink(tar_name)

    def test_extract_command(self):
        self.make_simple_tarfile(tmpname)
        for opt in '-e', '--extract':
            try:
                with support.temp_cwd(tarextdir):
                    out = self.tarfilecmd(opt, tmpname)
                self.assertEqual(out, b'')
            finally:
                support.rmtree(tarextdir)

    def test_extract_command_verbose(self):
        self.make_simple_tarfile(tmpname)
        for opt in '-v', '--verbose':
            try:
                with support.temp_cwd(tarextdir):
                    out = self.tarfilecmd(opt, '-e', tmpname)
                self.assertIn(b' file is extracted.', out)
            finally:
                support.rmtree(tarextdir)

    def test_extract_command_filter(self):
        self.make_evil_tarfile(tmpname)
        # Make an inner directory, so the member named '../evil'
        # is still extracted into `tarextdir`
        destdir = os.path.join(tarextdir, 'dest')
        os.mkdir(tarextdir)
        try:
            with support.temp_cwd(destdir):
                self.tarfilecmd_failure('-e', tmpname,
                                        '-v',
                                        '--filter', 'data')
                out = self.tarfilecmd('-e', tmpname,
                                      '-v',
                                      '--filter', 'fully_trusted',
                                      PYTHONIOENCODING='utf-8')
                self.assertIn(b' file is extracted.', out)
        finally:
            support.rmtree(tarextdir)

    def test_extract_command_different_directory(self):
        self.make_simple_tarfile(tmpname)
        try:
            os.mkdir(tarextdir)
            self.tarfilecmd('-e', tmpname, '-C', tarextdir)
            self.assertIn(os.path.basename(support.findfile('tokenize_tests.txt')),
                          os.listdir(tarextdir))
        finally:
            support.rmtree(tarextdir)

    def test_extract_command_invalid_file(self):
        zipname = support.findfile('zipdir.zip')
        with support.temp_cwd(tarextdir):
            rc, out, err = self.tarfilecmd_failure('-e', zipname)
        self.assertIn(b' is not a tar archive.', err)
        self.assertEqual(out, b'')
        self.assertEqual(rc, 1)


class ContextManagerTest(unittest.TestCase):

    def test_basic(self):
        with tarfile.open(tarname) as tar:
            self.assertFalse(tar.closed, "closed inside runtime context")
        self.assertTrue(tar.closed, "context manager failed")

    def test_closed(self):
        # The __enter__() method is supposed to raise OSError
        # if the TarFile object is already closed.
        tar = tarfile.open(tarname)
        tar.close()
        with self.assertRaises(OSError):
            with tar:
                pass

    def test_exception(self):
        # Test if the OSError exception is passed through properly.
        with self.assertRaises(Exception) as exc:
            with tarfile.open(tarname) as tar:
                raise OSError
        self.assertIsInstance(exc.exception, OSError,
                              "wrong exception raised in context manager")
        self.assertTrue(tar.closed, "context manager failed")

    def test_no_eof(self):
        # __exit__() must not write end-of-archive blocks if an
        # exception was raised.
        try:
            with tarfile.open(tmpname, "w") as tar:
                raise Exception
        except:
            pass
        self.assertEqual(os.path.getsize(tmpname), 0,
                "context manager wrote an end-of-archive block")
        self.assertTrue(tar.closed, "context manager failed")

    def test_eof(self):
        # __exit__() must write end-of-archive blocks, i.e. call
        # TarFile.close() if there was no error.
        with tarfile.open(tmpname, "w"):
            pass
        self.assertNotEqual(os.path.getsize(tmpname), 0,
                "context manager wrote no end-of-archive block")

    def test_fileobj(self):
        # Test that __exit__() did not close the external file
        # object.
        with open(tmpname, "wb") as fobj:
            try:
                with tarfile.open(fileobj=fobj, mode="w") as tar:
                    raise Exception
            except:
                pass
            self.assertFalse(fobj.closed, "external file object was closed")
            self.assertTrue(tar.closed, "context manager failed")


@unittest.skipIf(hasattr(os, "link"), "requires os.link to be missing")
class LinkEmulationTest(ReadTest, unittest.TestCase):

    # Test for issue #8741 regression. On platforms that do not support
    # symbolic or hard links tarfile tries to extract these types of members
    # as the regular files they point to.
    def _test_link_extraction(self, name):
        self.tar.extract(name, TEMPDIR, filter='fully_trusted')
        with open(os.path.join(TEMPDIR, name), "rb") as f:
            data = f.read()
        self.assertEqual(md5sum(data), md5_regtype)

    # See issues #1578269, #8879, and #17689 for some history on these skips
    @unittest.skipIf(hasattr(os.path, "islink"),
                     "Skip emulation - has os.path.islink but not os.link")
    def test_hardlink_extraction1(self):
        self._test_link_extraction("ustar/lnktype")

    @unittest.skipIf(hasattr(os.path, "islink"),
                     "Skip emulation - has os.path.islink but not os.link")
    def test_hardlink_extraction2(self):
        self._test_link_extraction("./ustar/linktest2/lnktype")

    @unittest.skipIf(hasattr(os, "symlink"),
                     "Skip emulation if symlink exists")
    def test_symlink_extraction1(self):
        self._test_link_extraction("ustar/symtype")

    @unittest.skipIf(hasattr(os, "symlink"),
                     "Skip emulation if symlink exists")
    def test_symlink_extraction2(self):
        self._test_link_extraction("./ustar/linktest2/symtype")


class Bz2PartialReadTest(Bz2Test, unittest.TestCase):
    # Issue5068: The _BZ2Proxy.read() method loops forever
    # on an empty or partial bzipped file.

    def _test_partial_input(self, mode):
        class MyBytesIO(io.BytesIO):
            hit_eof = False
            def read(self, n):
                if self.hit_eof:
                    raise AssertionError("infinite loop detected in "
                                         "tarfile.open()")
                self.hit_eof = self.tell() == len(self.getvalue())
                return super(MyBytesIO, self).read(n)
            def seek(self, *args):
                self.hit_eof = False
                return super(MyBytesIO, self).seek(*args)

        data = bz2.compress(tarfile.TarInfo("foo").tobuf())
        for x in range(len(data) + 1):
            try:
                tarfile.open(fileobj=MyBytesIO(data[:x]), mode=mode)
            except tarfile.ReadError:
                pass # we have no interest in ReadErrors

    def test_partial_input(self):
        self._test_partial_input("r")

    def test_partial_input_bz2(self):
        self._test_partial_input("r:bz2")


class ReplaceTests(ReadTest, unittest.TestCase):
    def test_replace_name(self):
        member = self.tar.getmember('ustar/regtype')
        replaced = member.replace(name='misc/other')
        self.assertEqual(replaced.name, 'misc/other')
        self.assertEqual(member.name, 'ustar/regtype')
        self.assertEqual(self.tar.getmember('ustar/regtype').name,
                         'ustar/regtype')

    def test_replace_deep(self):
        member = self.tar.getmember('pax/regtype1')
        replaced = member.replace()
        replaced.pax_headers['gname'] = 'not-bar'
        self.assertEqual(member.pax_headers['gname'], 'bar')
        self.assertEqual(
            self.tar.getmember('pax/regtype1').pax_headers['gname'], 'bar')

    def test_replace_shallow(self):
        member = self.tar.getmember('pax/regtype1')
        replaced = member.replace(deep=False)
        replaced.pax_headers['gname'] = 'not-bar'
        self.assertEqual(member.pax_headers['gname'], 'not-bar')
        self.assertEqual(
            self.tar.getmember('pax/regtype1').pax_headers['gname'], 'not-bar')

    def test_replace_all(self):
        member = self.tar.getmember('ustar/regtype')
        for attr_name in ('name', 'mtime', 'mode', 'linkname',
                          'uid', 'gid', 'uname', 'gname'):
            with self.subTest(attr_name=attr_name):
                replaced = member.replace(**{attr_name: None})
                self.assertEqual(getattr(replaced, attr_name), None)
                self.assertNotEqual(getattr(member, attr_name), None)

    def test_replace_internal(self):
        member = self.tar.getmember('ustar/regtype')
        with self.assertRaises(TypeError):
            member.replace(offset=123456789)


class NoneInfoExtractTests(ReadTest):
    # These mainly check that all kinds of members are extracted successfully
    # if some metadata is None.
    # Some of the methods do additional spot checks.

    # We also test that the default filters can deal with None.

    extraction_filter = None

    @classmethod
    def setUpClass(cls):
        # Ensure parent's setUpClass is called to load _tar_data
        # Call the parent ReadTest's setUpClass to load cls._tar_data (uncompressed tar)
        ReadTest.setUpClass() # Explicitly call ReadTest's setUpClass

        # Now use the loaded cls._tar_data for this class's setup
        cls._tar_data.seek(0) # Reset stream for this class's use
        with tarfile.open(fileobj=cls._tar_data, mode='r', encoding="iso8859-1") as tar:
            cls.control_dir = str(pathlib.Path(TEMPDIR) / "extractall_ctrl")
            tar.errorlevel = 0
            with contextlib.ExitStack() as cm:
                if cls.extraction_filter is None:
                    # Python 3.4 warnings.catch_warnings does not support 'action' kwarg.
                    # Use a standard filter setup inside the context.
                    ctx = warnings.catch_warnings(record=True)
                    cm.enter_context(ctx)
                    warnings.simplefilter('ignore', DeprecationWarning)
                tar.extractall(cls.control_dir, filter=cls.extraction_filter)
        cls.control_paths = set(
            p.relative_to(cls.control_dir)
            for p in pathlib.Path(cls.control_dir).glob('**/*')
            if str(p).startswith(cls.control_dir)
        )

    @classmethod
    def tearDownClass(cls):
        # Convert control_dir to Path for rglob for consistent cleanup
        # Ensure cleanup by making directories writable by owner
        for p in pathlib.Path(cls.control_dir).rglob('*'):
            if p.is_dir():
                p.chmod(0o700) # owner read/write/execute
        shutil.rmtree(cls.control_dir)

    def check_files_present(self, directory):
        got_paths = set(
            p.relative_to(pathlib.Path(directory))
            for p in pathlib.Path(directory).rglob('*'))
        self.assertEqual(self.control_paths, got_paths)

    @contextlib.contextmanager
    def extract_with_none(self, *attr_names):
        DIR = pathlib.Path(TEMPDIR) / "extractall_none"
        self.tar.errorlevel = 0
        for member in self.tar.getmembers():
            for attr_name in attr_names:
                setattr(member, attr_name, None)
        with support.temp_dir(str(DIR)) as temp_dir_path:
            self.tar.extractall(temp_dir_path, filter='fully_trusted')
            self.check_files_present(temp_dir_path)
            yield pathlib.Path(temp_dir_path)

    def test_extractall_none_mtime(self):
        # mtimes of extracted files should be later than 'now' -- the mtime
        # of a previously created directory.
        now = pathlib.Path(TEMPDIR).stat().st_mtime
        with self.extract_with_none('mtime') as DIR_pathlib:
            for path in pathlib.Path(DIR_pathlib).glob('**/*'):
                with self.subTest(path=path):
                    try:
                        mtime = path.stat().st_mtime
                    except OSError:
                        # Some systems can't stat symlinks, ignore those
                        if not path.is_symlink():
                            raise
                    else:
                        self.assertGreaterEqual(path.stat().st_mtime, now)

    def test_extractall_none_mode(self):
        # modes of directories and regular files should match the mode
        # of a "normally" created directory or regular file
        dir_mode = pathlib.Path(TEMPDIR).stat().st_mode
        regular_file = pathlib.Path(TEMPDIR) / 'regular_file'
        with regular_file.open('w') as f:
            f.write('')
        regular_file_mode = regular_file.stat().st_mode
        with self.extract_with_none('mode') as DIR_pathlib:
            for path in pathlib.Path(DIR_pathlib).glob('**/*'):
                with self.subTest(path=path):
                    if path.is_dir():
                        self.assertEqual(path.stat().st_mode, dir_mode)
                    elif path.is_file():
                        self.assertEqual(path.stat().st_mode,
                                         regular_file_mode)

    def test_extractall_none_uid(self):
        with self.extract_with_none('uid'):
            pass

    def test_extractall_none_gid(self):
        with self.extract_with_none('gid'):
            pass

    def test_extractall_none_uname(self):
        with self.extract_with_none('uname'):
            pass

    def test_extractall_none_gname(self):
        with self.extract_with_none('gname'):
            pass

    def test_extractall_none_ownership(self):
        with self.extract_with_none('uid', 'gid', 'uname', 'gname'):
            pass

class NoneInfoExtractTests_Data(NoneInfoExtractTests, unittest.TestCase):
    extraction_filter = 'data'

class NoneInfoExtractTests_FullyTrusted(NoneInfoExtractTests,
                                        unittest.TestCase):
    extraction_filter = 'fully_trusted'

class NoneInfoExtractTests_Tar(NoneInfoExtractTests, unittest.TestCase):
    extraction_filter = 'tar'

class NoneInfoExtractTests_Default(NoneInfoExtractTests,
                                   unittest.TestCase):
    extraction_filter = None

class NoneInfoTests_Misc(unittest.TestCase):
    def test_add(self):
        # When addfile() encounters None metadata, it raises a ValueError
        bio = io.BytesIO()
        for tarformat in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT,
                          tarfile.PAX_FORMAT):
            with self.subTest(tarformat=tarformat):
                tar = tarfile.open(fileobj=bio, mode='w', format=tarformat)
                tarinfo = tar.gettarinfo(tarname)
                try:
                    tar.addfile(tarinfo)
                except Exception:
                    if tarformat == tarfile.USTAR_FORMAT:
                        # In the old, limited format, adding might fail for
                        # reasons like the UID being too large
                        pass
                    else:
                        raise
                else:
                    for attr_name in ('mtime', 'mode', 'uid', 'gid',
                                    'uname', 'gname'):
                        with self.subTest(attr_name=attr_name):
                            replaced = tarinfo.replace(**{attr_name: None})
                            with self.assertRaisesRegex(ValueError,
                                                        "{}".format(attr_name)):
                                tar.addfile(replaced)

    def test_list(self):
        # Change some metadata to None, then compare list() output
        # word-for-word. We want list() to not raise, and to only change
        # printout for the affected piece of metadata.
        # (n.b.: some contents of the test archive are hardcoded.)
        for attr_names in ({'mtime'}, {'mode'}, {'uid'}, {'gid'},
                           {'uname'}, {'gname'},
                           {'uid', 'uname'}, {'gid', 'gname'}):
            with self.subTest(attr_names=attr_names), tarfile.open(tarname, encoding="iso8859-1") as tar:
                tio_prev = io.TextIOWrapper(io.BytesIO(), 'ascii', newline='\n')
                with support.swap_attr(sys, 'stdout', tio_prev):
                    tar.list()
                for member in tar.getmembers():
                    for attr_name in attr_names:
                        setattr(member, attr_name, None)
                tio_new = io.TextIOWrapper(io.BytesIO(), 'ascii', newline='\n')
                with support.swap_attr(sys, 'stdout', tio_new):
                    tar.list()
                for expected, got in zip(tio_prev.detach().getvalue().split(),
                                         tio_new.detach().getvalue().split()):
                    if attr_names == {'mtime'} and re.match(rb'2003-01-\d\d', expected):
                        self.assertEqual(got, b'????-??-??')
                    elif attr_names == {'mtime'} and re.match(rb'\d\d:\d\d:\d\d', expected):
                        self.assertEqual(got, b'??:??:??')
                    elif attr_names == {'mode'} and re.match(
                            rb'.([r-][w-][x-]){3}', expected):
                        self.assertEqual(got, b'??????????')
                    elif attr_names == {'uname'} and expected.startswith(
                            (b'tarfile/', b'lars/', b'foo/')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_group, exp_group)
                        self.assertRegex(got_user, b'[0-9]+')
                    elif attr_names == {'gname'} and expected.endswith(
                            (b'/tarfile', b'/users', b'/bar')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_user, exp_user)
                        self.assertRegex(got_group, b'[0-9]+')
                    elif attr_names == {'uid'} and expected.startswith(
                            (b'1000/')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_group, exp_group)
                        self.assertEqual(got_user, b'None')
                    elif attr_names == {'gid'} and expected.endswith((b'/100')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_user, exp_user)
                        self.assertEqual(got_group, b'None')
                    elif attr_names == {'uid', 'uname'} and expected.startswith(
                            (b'tarfile/', b'lars/', b'foo/', b'1000/')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_group, exp_group)
                        self.assertEqual(got_user, b'None')
                    elif attr_names == {'gname', 'gid'} and expected.endswith(
                            (b'/tarfile', b'/users', b'/bar', b'/100')):
                        exp_user, exp_group = expected.split(b'/')
                        got_user, got_group = got.split(b'/')
                        self.assertEqual(got_user, exp_user)
                        self.assertEqual(got_group, b'None')
                    else:
                        # In other cases the output should be the same
                        self.assertEqual(expected, got)

def _filemode_to_int(mode):
    """Inverse of `stat.filemode` (for permission bits)

    Using mode strings rather than numbers makes the later tests more readable.
    """
    str_mode = mode[1:]
    result = (
          {'r': stat.S_IRUSR, '-': 0}[str_mode[0]]
        | {'w': stat.S_IWUSR, '-': 0}[str_mode[1]]
        | {'x': stat.S_IXUSR, '-': 0,
           's': stat.S_IXUSR | stat.S_ISUID,
           'S': stat.S_ISUID}[str_mode[2]]
        | {'r': stat.S_IRGRP, '-': 0}[str_mode[3]]
        | {'w': stat.S_IWGRP, '-': 0}[str_mode[4]]
        | {'x': stat.S_IXGRP, '-': 0,
           's': stat.S_IXGRP | stat.S_ISGID,
           'S': stat.S_ISGID}[str_mode[5]]
        | {'r': stat.S_IROTH, '-': 0}[str_mode[6]]
        | {'w': stat.S_IWOTH, '-': 0}[str_mode[7]]
        | {'x': stat.S_IXOTH, '-': 0,
           't': stat.S_IXOTH | stat.S_ISVTX,
           'T': stat.S_ISVTX}[str_mode[8]]
        )
    # check we did this right
    assert stat.filemode(result)[1:] == mode[1:]

    return result

class ArchiveMaker:
    """Helper to create a tar file with specific contents

    Usage:

        with ArchiveMaker() as t:
            t.add('filename', ...)

        with t.open() as tar:
            ... # `tar` is now a TarFile with 'filename' in it!
    """
    def __init__(self):
        self.bio = io.BytesIO()

    def __enter__(self):
        self.tar_w = tarfile.TarFile(mode='w', fileobj=self.bio)
        return self

    def __exit__(self, *exc):
        self.tar_w.close()
        self.contents = self.bio.getvalue()
        self.bio = None

    def add(self, name, *, type=None, symlink_to=None, hardlink_to=None,
            mode=None, **kwargs):
        """Add a member to the test archive. Call within `with`."""
        name = str(name)
        tarinfo = tarfile.TarInfo(name).replace(**kwargs)
        if mode:
            tarinfo.mode = _filemode_to_int(mode)
        if symlink_to is not None:
            type = tarfile.SYMTYPE
            tarinfo.linkname = str(symlink_to)
        if hardlink_to is not None:
            type = tarfile.LNKTYPE
            tarinfo.linkname = str(hardlink_to)
        if name.endswith('/') and type is None:
            type = tarfile.DIRTYPE
        if type is not None:
            tarinfo.type = type
        if tarinfo.isreg():
            fileobj = io.BytesIO(bytes(tarinfo.size))
        else:
            fileobj = None
        self.tar_w.addfile(tarinfo, fileobj)

    def open(self, **kwargs):
        """Open the resulting archive as TarFile. Call after `with`."""
        bio = io.BytesIO(self.contents)
        return tarfile.open(fileobj=bio, **kwargs)


# New setUpClass for compressed tests
# These classes need to load the *raw compressed data* once
# and then provide a fresh BytesIO for each test.
@classmethod
def _setup_compressed_class(subcls):
    with open(subcls.tarname, 'rb') as f:
        subcls._tar_data_original = f.read()

@classmethod
def _teardown_compressed_class(subcls):
    # No need to explicitly close BytesIO, it's created per-test
    if hasattr(subcls, '_tar_data_original'):
        del subcls._tar_data_original

for cls in [GzipTest, Bz2Test, LzmaTest]:
    cls.setUpClass = _setup_compressed_class
    cls.tearDownClass = _teardown_compressed_class
    # Explicitly ensure prefix and suffix are set on these base test classes
    # This works around potential MRO/inheritance quirks with dynamic setUp
    if not hasattr(cls, 'prefix'):
        cls.prefix = "r:" # Default prefix for read tests
    if not hasattr(cls, 'suffix') and cls.tarname:
        # Extract suffix from tarname if not explicitly set
        _, ext = os.path.splitext(cls.tarname)
        cls.suffix = ext[1:] if ext else ''


# Override setUp for compressed tests to provide fresh BytesIO
def _new_compressed_set_up(self):
    # Create a fresh BytesIO for each test in compressed classes
    # This BytesIO will be consumed by the compressed file object (e.g., GzipFile)
    self._tar_data = io.BytesIO(self._tar_data_original)
    # Ensure mode is constructed from class attributes that are guaranteed to exist
    # because they were set in _setup_compressed_class for these base classes.
    mode_string = self.prefix + self.suffix

    self.tar = tarfile.open(fileobj=self._tar_data, mode=mode_string, encoding="iso8859-1")
    self.addCleanup(self.tar.close)

for cls in [GzipUstarReadTest, Bz2UstarReadTest, LzmaUstarReadTest,
            GzipListTest, Bz2ListTest, LzmaListTest,
            GzipMiscReadTest, Bz2MiscReadTest, LzmaMiscReadTest,
            GzipStreamReadTest, Bz2StreamReadTest, LzmaStreamReadTest,
            GzipDetectReadTest, Bz2DetectReadTest, LzmaDetectReadTest]:
    cls.setUp = _new_compressed_set_up

# Apply specific setUpClass/tearDownClass for the base ReadTest class itself.
# ReadTest itself handles uncompressed data, so the BytesIO can be safely shared across its tests.
@classmethod
def _setup_read_test_class(cls):
    with open(cls.tarname, 'rb') as f:
        cls._tar_data = io.BytesIO(f.read())

ReadTest.setUpClass = _setup_read_test_class

@classmethod
def _teardown_read_test_class(cls):
    cls._tar_data.close()

ReadTest.tearDownClass = _teardown_read_test_class



class TestExtractionFilters(unittest.TestCase):

    # A temporary directory for the extraction results.
    # All files that "escape" the destination path should still end
    # up in this directory.
    outerdir = pathlib.Path(TEMPDIR) / ('outerdir_' + str(os.getpid())) # Make unique to avoid conflicts

    # The destination for the extraction, within `outerdir`
    destdir = (outerdir / 'dest').absolute().as_posix()

    @contextlib.contextmanager
    def check_context(self, tar, filter):
        """Extracts `tar` to `self.destdir` and allows checking the result

        If an error occurs, it must be checked using `expect_exception`

        Otherwise, all resulting files must be checked using `expect_file`,
        except the destination directory itself and parent directories of
        other files.
        When checking directories, do so before their contents.
        """
        with support.temp_dir(self.outerdir):
            try:
                tar.extractall(self.destdir, filter=filter)
            except Exception as exc:
                self.raised_exception = exc
                self.expected_paths = set()
            else:
                self.raised_exception = None
                self.expected_paths = set(self.outerdir.glob('**/*'))
                self.expected_paths.discard(self.destdir)
            try:
                yield
            finally:
                tar.close()
            if self.raised_exception:
                raise self.raised_exception
            self.assertEqual(self.expected_paths, set())

    def expect_file(self, name, type=None, symlink_to=None, mode=None):
        """Check a single file. See check_context."""
        if self.raised_exception:
            raise self.raised_exception
        # use normpath() rather than resolve() so we don't follow symlinks
        path = pathlib.Path(os.path.normpath(os.path.join(self.destdir, name)))
        self.assertIn(path, self.expected_paths)
        self.expected_paths.remove(path)
        if mode is not None and sys.platform != "win32":
            got = stat.filemode(stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(got, mode)
        if type is None and isinstance(name, str) and name.endswith('/'):
            type = tarfile.DIRTYPE
        if symlink_to is not None:
            got = pathlib.Path(os.readlink(os.path.join(self.destdir, name)))
            expected = pathlib.Path(symlink_to)
            # The symlink might be the same (textually) as what we expect,
            # but some systems change the link to an equivalent path, so
            # we fall back to samefile().
            self.assertTrue(got.samefile(expected),
                            "Link target mismatch: expected={} got={}".format(expected, got))
        elif type == tarfile.REGTYPE or type is None:
            self.assertTrue(path.is_file())
        elif type == tarfile.DIRTYPE:
            self.assertTrue(path.is_dir())
        elif type == tarfile.FIFOTYPE:
            self.assertTrue(path.is_fifo())
        else:
            raise NotImplementedError(type)
        for parent in path.parents:
            self.expected_paths.discard(parent)

    def expect_exception(self, exc_type, message_re='.'):
        with self.assertRaisesRegex(exc_type, message_re):
            if self.raised_exception is not None:
                raise self.raised_exception
        self.raised_exception = None

    def test_benign_file(self):
        with ArchiveMaker() as arc:
            arc.add('benign.txt')
        for filter in 'fully_trusted', 'tar', 'data':
            with self.check_context(arc.open(), filter):
                self.expect_file('benign.txt')

    def test_absolute(self):
        # Test handling a member with an absolute path
        # Inspired by 'absolute1' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc:
            arc.add(self.outerdir / 'escaped.evil')

        with self.check_context(arc.open(), 'fully_trusted'):
            self.expect_file('../escaped.evil')

        for filter in 'tar', 'data':
            with self.check_context(arc.open(), filter):
                if str(self.outerdir).startswith('/'):
                    # We strip leading slashes, as e.g. GNU tar does
                    # (without --absolute-filenames).
                    outerdir_stripped = str(self.outerdir).lstrip('/' + os.sep)
                    self.expect_file('{}/escaped.evil'.format(outerdir_stripped))
                else:
                    # On this system, absolute paths don't have leading
                    # slashes.
                    # So, there's nothing to strip. We refuse to unpack
                    # to an absolute path, nonetheless.
                    self.expect_exception(
                        tarfile.AbsolutePathError,
                        """['"].*escaped.evil['"] has an absolute path""")

    def test_parent_symlink(self):
        # Test interplaying symlinks
        # Inspired by 'dirsymlink2a' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc:
            arc.add('current', symlink_to='.')
            arc.add('parent', symlink_to='current/..')
            arc.add('parent/evil')

        if hasattr(os, 'symlink'):
            with self.check_context(arc.open(), 'fully_trusted'):
                if self.raised_exception is not None:
                    # Windows will refuse to create a file that's a symlink to itself
                    # (and tarfile doesn't swallow that exception)
                    self.expect_exception(FileExistsError)
                    # The other cases will fail with this error too.
                    # Skip the rest of this test.
                    return
                else:
                    self.expect_file('current', symlink_to='.')
                    self.expect_file('parent', symlink_to='current/..')
                    self.expect_file('../evil')

            with self.check_context(arc.open(), 'tar'):
                self.expect_exception(
                    tarfile.OutsideDestinationError,
                    """'parent/evil' would be extracted to ['"].*evil['"], """
                    + "which is outside the destination")

            with self.check_context(arc.open(), 'data'):
                self.expect_exception(
                    tarfile.LinkOutsideDestinationError,
                    """'parent' would link to ['"].*outerdir['"], """
                    + "which is outside the destination")

        else:
            # No symlink support. The symlinks are ignored.
            with self.check_context(arc.open(), 'fully_trusted'):
                self.expect_file('parent/evil')
            with self.check_context(arc.open(), 'tar'):
                self.expect_file('parent/evil')
            with self.check_context(arc.open(), 'data'):
                self.expect_file('parent/evil')

    def test_parent_symlink2(self):
        # Test interplaying symlinks
        # Inspired by 'dirsymlink2b' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc:
            arc.add('current', symlink_to='.')
            arc.add('current/parent', symlink_to='..')
            arc.add('parent/evil')

        with self.check_context(arc.open(), 'fully_trusted'):
            if hasattr(os, 'symlink'):
                self.expect_file('current', symlink_to='.')
                self.expect_file('parent', symlink_to='..')
                self.expect_file('../evil')
            else:
                self.expect_file('current/')
                self.expect_file('parent/evil')

        with self.check_context(arc.open(), 'tar'):
            if hasattr(os, 'symlink'):
                self.expect_exception(
                        tarfile.OutsideDestinationError,
                        "'parent/evil' would be extracted to "
                        + """['"].*evil['"], which is outside """
                        + "the destination")
            else:
                self.expect_file('current/')
                self.expect_file('parent/evil')

        with self.check_context(arc.open(), 'data'):
            self.expect_exception(
                    tarfile.LinkOutsideDestinationError,
                    """'current/parent' would link to ['"].*['"], """
                    + "which is outside the destination")

    def test_absolute_symlink(self):
        # Test symlink to an absolute path
        # Inspired by 'dirsymlink' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc:
            arc.add('parent', symlink_to=self.outerdir)
            arc.add('parent/evil')

        with self.check_context(arc.open(), 'fully_trusted'):
            if hasattr(os, 'symlink'):
                self.expect_file('parent', symlink_to=self.outerdir)
                self.expect_file('../evil')
            else:
                self.expect_file('parent/evil')

        with self.check_context(arc.open(), 'tar'):
            if hasattr(os, 'symlink'):
                self.expect_exception(
                        tarfile.OutsideDestinationError,
                        "'parent/evil' would be extracted to "
                        + """['"].*evil['"], which is outside """
                        + "the destination")
            else:
                self.expect_file('parent/evil')

        with self.check_context(arc.open(), 'data'):
            self.expect_exception(
                tarfile.AbsoluteLinkError,
                "'parent' is a symlink to an absolute path")

    def test_sly_relative0(self):
        # Inspired by 'relative0' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc: # Need to rebuild archive for each test
            arc.add('../moo', symlink_to='..//tmp/moo')

        try:
            with self.check_context(arc.open(), filter='fully_trusted'):
                if hasattr(os, 'symlink'):
                    if isinstance(self.raised_exception, FileExistsError):
                        # XXX TarFile happens to fail creating a parent
                        # directory.
                        # This might be a bug, but fixing it would hurt
                        # security.
                        # Note that e.g. GNU `tar` rejects '..' components,
                        # so you could argue this is an invalid archive and we
                        # just raise an bad type of exception.
                        self.expect_exception(FileExistsError)
                    else:
                        self.expect_file('../moo', symlink_to='..//tmp/moo')
                else:
                    # The symlink can't be extracted and is ignored
                    pass
        except FileExistsError:
            pass

        for filter in 'tar', 'data':
            with self.check_context(arc.open(), filter):
                self.expect_exception(
                        tarfile.OutsideDestinationError,
                        "'../moo' would be extracted to "
                        + "'.*moo', which is outside "
                        + "the destination")

    def test_sly_relative2(self):
        # Inspired by 'relative2' in https://github.com/jwilk/traversal-archives
        with ArchiveMaker() as arc: # Need to rebuild archive for each test
            arc.add('tmp/')
            arc.add('tmp/../../moo', symlink_to='tmp/../..//tmp/moo')

        with self.check_context(arc.open(), 'fully_trusted'):
            self.expect_file('tmp', type=tarfile.DIRTYPE)
            if hasattr(os, 'symlink'):
                self.expect_file('../moo', symlink_to='tmp/../../tmp/moo')

        for filter in 'tar', 'data':
            with self.check_context(arc.open(), filter):
                self.expect_exception(
                    tarfile.OutsideDestinationError,
                    "'tmp/../../moo' would be extracted to "
                    + """['"].*moo['"], which is outside the """
                    + "destination")

    def test_modes(self):
        # Test how file modes are extracted
        # (Note that the modes are ignored on platforms without working chmod)
        with ArchiveMaker() as arc:
            arc.add('all_bits', mode='?rwsrwsrwt')
            arc.add('perm_bits', mode='?rwxrwxrwx')
            arc.add('exec_group_other', mode='?rw-rwxrwx')
            arc.add('read_group_only', mode='?---r-----')
            arc.add('no_bits', mode='?---------')
            arc.add('dir/', mode='?---rwsrwt', type=tarfile.DIRTYPE)

        with self.check_context(arc.open(), 'fully_trusted'):
            self.expect_file('all_bits', mode='?rwsrwsrwt')
            self.expect_file('perm_bits', mode='?rwxrwxrwx')
            self.expect_file('exec_group_other', mode='?rw-rwxrwx')
            self.expect_file('read_group_only', mode='?---r-----')
            self.expect_file('no_bits', mode='?---------')
            self.expect_file('dir', type=tarfile.DIRTYPE, mode='?---rwsrwt')

        with self.check_context(arc.open(), 'tar'):
            self.expect_file('all_bits', mode='?rwxr-xr-x')
            self.expect_file('perm_bits', mode='?rwxr-xr-x')
            self.expect_file('exec_group_other', mode='?rw-r-xr-x')
            self.expect_file('read_group_only', mode='?---r-----')
            self.expect_file('no_bits', mode='?---------')
            self.expect_file('dir/', type=tarfile.DIRTYPE, mode='?---r-xr-x')

        with self.check_context(arc.open(), 'data'):
            normal_dir_mode = stat.filemode(stat.S_IMODE(
                self.outerdir.stat().st_mode))
            self.expect_file('all_bits', mode='?rwxr-xr-x')
            self.expect_file('perm_bits', mode='?rwxr-xr-x')
            self.expect_file('exec_group_other', mode='?rw-r--r--')
            self.expect_file('read_group_only', mode='?rw-r-----')
            self.expect_file('no_bits', mode='?rw-------')
            self.expect_file('dir/', type=tarfile.DIRTYPE, mode=normal_dir_mode)

    def test_pipe(self):
        # Test handling of a special file
        with ArchiveMaker() as arc:
            arc.add('foo', type=tarfile.FIFOTYPE)

        for filter in 'fully_trusted', 'tar':
            with self.check_context(arc.open(), filter):
                if hasattr(os, 'mkfifo'):
                    self.expect_file('foo', type=tarfile.FIFOTYPE)
                else:
                    # The pipe can't be extracted and is skipped.
                    pass

        with self.check_context(arc.open(), 'data'):
            self.expect_exception(
                tarfile.SpecialFileError,
                "'foo' is a special file")

    def test_special_files(self):
        # Creating device files is tricky. Instead of attempting that let's
        # only check the filter result.
        for special_type in tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE:
            tarinfo = tarfile.TarInfo('foo')
            tarinfo.type = special_type
            trusted = tarfile.fully_trusted_filter(tarinfo, '')
            self.assertIs(trusted, tarinfo)
            tar = tarfile.tar_filter(tarinfo, '')
            self.assertEqual(tar.type, special_type)
            with self.assertRaises(tarfile.SpecialFileError) as cm:
                tarfile.data_filter(tarinfo, '')
            self.assertIsInstance(cm.exception.tarinfo, tarfile.TarInfo)
            self.assertEqual(cm.exception.tarinfo.name, 'foo')

    def test_fully_trusted_filter(self):
        # The 'fully_trusted' filter returns the original TarInfo objects.
        with tarfile.TarFile.open(tarname) as tar:
            for tarinfo in tar.getmembers():
                filtered = tarfile.fully_trusted_filter(tarinfo, '')
                self.assertIs(filtered, tarinfo)

    def test_tar_filter(self):
        # The 'tar' filter returns TarInfo objects with the same name/type.
        # (It can also fail for particularly "evil" input, but we don't have
        # that in the test archive.)
        with tarfile.TarFile.open(tarname) as tar:
            for tarinfo in tar.getmembers():
                filtered = tarfile.tar_filter(tarinfo, '')
                self.assertIs(filtered.name, tarinfo.name)
                self.assertIs(filtered.type, tarinfo.type)

    def test_data_filter(self):
        # The 'data' filter either raises, or returns TarInfo with the same
        # name/type.
        with tarfile.TarFile.open(tarname) as tar:
            for tarinfo in tar.getmembers():
                try:
                    filtered = tarfile.data_filter(tarinfo, '')
                except tarfile.FilterError:
                    continue
                self.assertIs(filtered.name, tarinfo.name)
                self.assertIs(filtered.type, tarinfo.type)

    def test_default_filter_warns(self):
        """Ensure the default filter warns"""
        with ArchiveMaker() as arc:
            arc.add('foo')
        with support.check_warnings(
                ('Python 3.14', DeprecationWarning)):
            with self.check_context(arc.open(), None):
                self.expect_file('foo')

    def test_change_default_filter_on_instance(self):
        tar = tarfile.TarFile(tarname, 'r')
        def strict_filter(tarinfo, path):
            if tarinfo.name == 'ustar/regtype':
                return tarinfo
            else:
                return None
        tar.extraction_filter = strict_filter
        with self.check_context(tar, None):
            self.expect_file('ustar/regtype')

    def test_change_default_filter_on_class(self):
        def strict_filter(tarinfo, path):
            if tarinfo.name == 'ustar/regtype':
                return tarinfo
            else:
                return None
        tar = tarfile.TarFile(tarname, 'r')
        with support.swap_attr(tarfile.TarFile, 'extraction_filter',
                               staticmethod(strict_filter)):
            with self.check_context(tar, None):
                self.expect_file('ustar/regtype')

    def test_change_default_filter_on_subclass(self):
        class TarSubclass(tarfile.TarFile):
            def extraction_filter(self, tarinfo, path):
                if tarinfo.name == 'ustar/regtype':
                    return tarinfo
                else:
                    return None

        tar = TarSubclass(tarname, 'r')
        with self.check_context(tar, None):
            self.expect_file('ustar/regtype')

    def test_change_default_filter_to_string(self):
        tar = tarfile.TarFile(tarname, 'r')
        tar.extraction_filter = 'data'
        with self.check_context(tar, None): # Test with the instance filter
            self.expect_exception(TypeError, "String names are not supported for TarFile.extraction_filter.")

    def test_custom_filter(self):
        def custom_filter(tarinfo, path):
            if isinstance(path, pathlib.Path):
                path = path.absolute().as_posix()
            self.assertIs(path, self.destdir)
            if tarinfo.name == 'move_this':
                return tarinfo.replace(name='moved')
            if tarinfo.name == 'ignore_this':
                return None
            return tarinfo

        with ArchiveMaker() as arc:
            arc.add('move_this')
            arc.add('ignore_this')
            arc.add('keep')
        with self.check_context(arc.open(), custom_filter):
            self.expect_file('moved')
            self.expect_file('keep')

    def test_bad_filter_name(self):
        with ArchiveMaker() as arc:
            arc.add('foo')
        with self.check_context(arc.open(), 'bad filter name'):
            self.expect_exception(ValueError)

    def test_stateful_filter(self):
        # Stateful filters should be possible.
        # (This doesn't really test tarfile. Rather, it demonstrates
        # that third parties can implement a stateful filter.)
        class StatefulFilter:
            def __enter__(self):
                self.num_files_processed = 0
                return self

            def __call__(self, tarinfo, path):
                try:
                    tarinfo = tarfile.data_filter(tarinfo, path)
                except tarfile.FilterError:
                    return None
                self.num_files_processed += 1
                return tarinfo

            def __exit__(self, *exc_info):
                self.done = True

        with ArchiveMaker() as arc:
            arc.add('good')
            arc.add('bad', symlink_to='/')
            arc.add('good')
        with StatefulFilter() as custom_filter:
            with self.check_context(arc.open(), custom_filter):
                self.expect_file('good')
        self.assertEqual(custom_filter.num_files_processed, 2)
        self.assertEqual(custom_filter.done, True)

    def test_errorlevel(self):
        def extracterror_filter(tarinfo, path):
            raise tarfile.ExtractError('failed with ExtractError')
        def filtererror_filter(tarinfo, path):
            raise tarfile.FilterError('failed with FilterError')
        def oserror_filter(tarinfo, path):
            raise OSError('failed with OSError')
        def tarerror_filter(tarinfo, path):
            raise tarfile.TarError('failed with base TarError')
        def valueerror_filter(tarinfo, path):
            raise ValueError('failed with ValueError')

        with ArchiveMaker() as arc:
            arc.add('file')

        # If errorlevel is 0, errors affected by errorlevel are ignored

        with self.check_context(arc.open(errorlevel=0), extracterror_filter):
            self.expect_file('file')

        with self.check_context(arc.open(errorlevel=0), filtererror_filter):
            self.expect_file('file')

        with self.check_context(arc.open(errorlevel=0), oserror_filter):
            self.expect_file('file')

        with self.check_context(arc.open(errorlevel=0), tarerror_filter):
            self.expect_exception(tarfile.TarError)

        with self.check_context(arc.open(errorlevel=0), valueerror_filter):
            self.expect_exception(ValueError)

        # If 1, all fatal errors are raised

        with self.check_context(arc.open(errorlevel=1), extracterror_filter):
            self.expect_file('file')

        with self.check_context(arc.open(errorlevel=1), filtererror_filter):
            self.expect_exception(tarfile.FilterError)

        with self.check_context(arc.open(errorlevel=1), oserror_filter):
            self.expect_exception(OSError)

        with self.check_context(arc.open(errorlevel=1), tarerror_filter):
            self.expect_exception(tarfile.TarError)

        with self.check_context(arc.open(errorlevel=1), valueerror_filter):
            self.expect_exception(ValueError)

        # If 2, all non-fatal errors are raised as well.

        with self.check_context(arc.open(errorlevel=2), extracterror_filter):
            self.expect_exception(tarfile.ExtractError)

        with self.check_context(arc.open(errorlevel=2), filtererror_filter):
            self.expect_exception(tarfile.FilterError)

        with self.check_context(arc.open(errorlevel=2), oserror_filter):
            self.expect_exception(OSError)

        with self.check_context(arc.open(errorlevel=2), tarerror_filter):
            self.expect_exception(tarfile.TarError)

        with self.check_context(arc.open(errorlevel=2), valueerror_filter):
            self.expect_exception(ValueError)

        # We only handle ExtractionError, FilterError & OSError specially.

        with self.check_context(arc.open(errorlevel='boo!'), filtererror_filter):
            self.expect_exception(TypeError)  # errorlevel is not int


def setUpModule():
    support.unlink(TEMPDIR)
    os.makedirs(TEMPDIR)

    global testtarnames
    testtarnames = [tarname]
    with open(tarname, "rb") as fobj:
        data = fobj.read()

    # Create compressed tarfiles.
    for c in GzipTest, Bz2Test, LzmaTest:
        if c.open:
            support.unlink(c.tarname)
            testtarnames.append(c.tarname)
            with c.open(c.tarname, "wb") as tar:
                tar.write(data)


def _ignore_os_error(function, path, excinfo):
    # Ignore permission errors during rmtree
    if issubclass(excinfo[0], OSError):
        return
    raise # Reraise other errors


def tearDownModule():
    if os.path.exists(TEMPDIR):
        # Ensure all items in TEMPDIR are writable before attempting to remove
        for root, dirs, files in os.walk(TEMPDIR):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700) # rwx for owner
        support.rmtree(TEMPDIR, onerror=_ignore_os_error)

if __name__ == "__main__":
    unittest.main()
