import io, struct
from typing import Dict, Type, Union


from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection


class Binary:
    magics: Dict[bytes, Type["Binary"]] = {}

    def __new__(cls, path):
        if cls is Binary:
            with open(path, "rb") as f:
                cl = cls.magics[f.read(4)]
            return cl(path)
        else:
            return super().__new__(cls)

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.magic = Binary.magics[f.read(4)]

    def arch(self):
        pass

    def maps(self):
        pass

    def threads(self):
        pass


class BinaryException(Exception):
    """
    Binary file exception
    """

    pass


class CGCElf(Binary):
    @staticmethod
    def _cgc2elf(filename):
        # hack begin so we can use upstream Elftool
        with open(filename, "rb") as fd:
            stream = io.BytesIO(fd.read())
            stream.write(b"\x7fELF")
            stream.name = fd.name
            return stream

    def __init__(self, filename):
        super().__init__(filename)
        stream = self._cgc2elf(filename)
        self.elf = ELFFile(stream)
        self.arch = {"x86": "i386", "x64": "amd64"}[self.elf.get_machine_arch()]

        assert "i386" == self.arch
        assert self.elf.header.e_type in ["ET_EXEC"]

    def maps(self):
        for elf_segment in self.elf.iter_segments():
            if elf_segment.header.p_type not in ["PT_LOAD", "PT_NULL", "PT_PHDR", "PT_CGCPOV2"]:
                raise BinaryException("Not Supported Section")

            if elf_segment.header.p_type != "PT_LOAD" or elf_segment.header.p_memsz == 0:
                continue

            flags = elf_segment.header.p_flags
            # PF_X 0x1 Execute - PF_W 0x2 Write - PF_R 0x4 Read
            perms = ["   ", "  x", " w ", " wx", "r  ", "r x", "rw ", "rwx"][flags & 7]
            if "r" not in perms:
                raise BinaryException("Not readable map from cgc elf not supported")

            # CGCMAP--
            assert elf_segment.header.p_filesz != 0 or elf_segment.header.p_memsz != 0
            yield (
                (
                    elf_segment.header.p_vaddr,
                    elf_segment.header.p_memsz,
                    perms,
                    elf_segment.stream.name,
                    elf_segment.header.p_offset,
                    elf_segment.header.p_filesz,
                )
            )

    def threads(self):
        yield (("Running", {"EIP": self.elf.header.e_entry}))


class Elf(Binary):
    def __init__(self, filename):
        super().__init__(filename)
        self.elf = ELFFile(open(filename, "rb"))
        self.arch = {"x86": "i386", "x64": "amd64"}[self.elf.get_machine_arch()]
        assert self.elf.header.e_type in ["ET_DYN", "ET_EXEC", "ET_CORE"]

        # Get interpreter elf
        self.interpreter = None
        for elf_segment in self.elf.iter_segments():
            if elf_segment.header.p_type != "PT_INTERP":
                continue
            self.interpreter = Elf(elf_segment.data()[:-1])
            break
        if self.interpreter is not None:
            assert self.interpreter.arch == self.arch
            assert self.interpreter.elf.header.e_type in ["ET_DYN", "ET_EXEC"]

    def __del__(self):
        if self.elf is not None:
            self.elf.stream.close()

    def maps(self):
        for elf_segment in self.elf.iter_segments():
            if elf_segment.header.p_type != "PT_LOAD" or elf_segment.header.p_memsz == 0:
                continue

            flags = elf_segment.header.p_flags
            # PF_X 0x1 Execute - PF_W 0x2 Write - PF_R 0x4 Read
            perms = ["   ", "  x", " w ", " wx", "r  ", "r x", "rw ", "rwx"][flags & 7]
            if "r" not in perms:
                raise BinaryException("Not readable map from cgc elf not supported")

            # CGCMAP--
            assert elf_segment.header.p_filesz != 0 or elf_segment.header.p_memsz != 0
            yield (
                (
                    elf_segment.header.p_vaddr,
                    elf_segment.header.p_memsz,
                    perms,
                    elf_segment.stream.name,
                    elf_segment.header.p_offset,
                    elf_segment.header.p_filesz,
                )
            )

    def getInterpreter(self):
        return self.interpreter

    def threads(self):
        if self.elf.header.e_type in ("ET_DYN", "ET_EXEC"):
            yield (("Running", {"EIP": self.elf.header.e_entry}))
        else:
            threads = []
            for section in self.elf.iter_sections():
                if isinstance(section, NoteSection):
                    for note in section.iter_notes():
                        if note["n_type"] == "NT_PRSTATUS":
                            thread = {}
                            threads.append(thread)
                            x = io.BytesIO(bytes(note["n_desc"], encoding='utf-8'))
                            si_signo = struct.unpack("<L", x.read(4))
                            si_code = struct.unpack("<L", x.read(4))
                            si_errno = struct.unpack("<L", x.read(4))
                            pr_cursig = struct.unpack("<L", x.read(4))

                            pr_sigpend = struct.unpack("<Q", x.read(8))
                            pr_sighold = struct.unpack("<Q", x.read(8))

                            pr_pid = struct.unpack("<L", x.read(4)),
                            pr_ppid = struct.unpack("<L", x.read(4))
                            pr_pgrp = struct.unpack("<L", x.read(4))
                            pr_psid = struct.unpack("<L", x.read(4))


                            pr_utime = struct.unpack("<QQ", x.read(16))
                            pr_stime = struct.unpack("<QQ", x.read(16))
                            pr_cutime = struct.unpack("<QQ", x.read(16))
                            pr_cstime = struct.unpack("<QQ", x.read(16))

                            R15 = struct.unpack("<Q", x.read(8))[0]
                            R14 = struct.unpack("<Q", x.read(8))[0]
                            R13 = struct.unpack("<Q", x.read(8))[0]
                            R12 = struct.unpack("<Q", x.read(8))[0]
                            RBP = struct.unpack("<Q", x.read(8))[0]
                            RBX = struct.unpack("<Q", x.read(8))[0]
                            R11 = struct.unpack("<Q", x.read(8))[0]
                            RBX = struct.unpack("<Q", x.read(8))[0]
                            R10 = struct.unpack("<Q", x.read(8))[0]
                            R9 = struct.unpack("<Q", x.read(8))[0]
                            R8 = struct.unpack("<Q", x.read(8))[0]
                            RAX = struct.unpack("<Q", x.read(8))[0]
                            RCX = struct.unpack("<Q", x.read(8))[0]
                            RDX = struct.unpack("<Q", x.read(8))[0]
                            RSI = struct.unpack("<Q", x.read(8))[0]
                            RDI = struct.unpack("<Q", x.read(8))[0]
                            UNK = struct.unpack("<Q", x.read(8))[0]
                            RIP = struct.unpack("<Q", x.read(8))[0]
                            CS = struct.unpack("<Q", x.read(8))[0]
                            EFLAGS = struct.unpack("<Q", x.read(8))[0]
                            RSP = struct.unpack("<Q", x.read(8))[0]
                            SS = struct.unpack("<Q", x.read(8))[0]
                            FS = struct.unpack("<Q", x.read(8))[0]
                            GS = struct.unpack("<Q", x.read(8))[0]
                            DS = struct.unpack("<Q", x.read(8))[0]
                            ES = struct.unpack("<Q", x.read(8))[0]
                            thread["RAX"] = RAX
                            thread["RBX"] = RBX
                            thread["RCX"] = RCX
                            thread["RDX"] = RDX
                            thread["RSI"] = RSI
                            thread["RDI"] = RDI
                            thread["RSP"] = RSP
                            thread["RBP"] = RBP
                            thread["R8"] = R9
                            thread["R9"] = R9
                            thread["R10"] = R10
                            thread["R11"] = R11
                            thread["R12"] = R12
                            thread["R13"] = R13
                            thread["R14"] = R14
                            thread["R15"] = R15
                            thread["RIP"] = RIP
                            thread["EFLAGS"] = EFLAGS
                        #else:
                        #    print ("unknown note ", note["n_type"])
                    for t in threads:
                        yield t


Binary.magics = {b"\x7fCGC": CGCElf, b"\x7fELF": Elf}
