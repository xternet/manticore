from collections import namedtuple
from typing import Any, NamedTuple
import sys, struct
from manticore.core.manticore import ManticoreBase
from manticore.binary import Elf
from manticore.native.cpu.cpufactory import CpuFactory
from manticore.native.memory import (
    SMemory32,
    SMemory64,
    Memory32,
    Memory64,
    LazySMemory32,
    LazySMemory64,
)
from manticore.core.smtlib import *
from manticore.core.state import StateBase, Concretize, TerminateState
from manticore.utils.event import Eventful
from manticore.utils.log import set_verbosity
from manticore.native.memory import ConcretizeMemory, MemoryException

set_verbosity(9)

class CheckpointData(NamedTuple):
    pc: Any
    last_pc: Any

################ Script #######################
class NoOS(Eventful):
    def __init__(self, constraints, coredump):
        core = Elf(coredump)
        self.constraints = constraints
        self.cpu = self._mk_proc(core.arch)
        self.memory = self.cpu.memory

        for (vaddr, memsz, perms, name, offset, filesz) in core.maps():
            self.memory.mmapFile(vaddr, memsz, perms, name, offset)

        for thread in core.threads():
            for name, value in thread.items():
                self.cpu.write_register(name, value)

        super().__init__()

    def __getstate__(self):
        state = super().__getstate__()
        state['cpu'] = self.cpu
        state['constraints'] = self.constraints
        return state

    def __setstate__(self, state):
        super().__setstate__(state)
        self.cpu = state['cpu']
        self.constraints = state['constraints']
        self.memory = self.cpu.memory

    def execute(self):
        self.cpu.execute()

    def _mk_proc(self, arch: str):
        mem = Memory32() if arch in {"i386", "armv7"} else Memory64()
        cpu = CpuFactory.get_cpu(mem, arch)
        return cpu

    @property
    def current(self):
        assert self._current is not None
        return self.procs[self._current]


class StateNoOS(StateBase):
    def __init__(self, coredump):
        constraints = ConstraintSet()
        platform = NoOS(constraints, coredump)
        super().__init__(constraints, platform)

    @property
    def cpu(self):
        return self.platform.cpu

    @property
    def memory(self):
        return self.platform.memory

    def _rollback(self, checkpoint_data: CheckpointData) -> None:
        """
        Rollback state to previous values in checkpoint_data
        """
        # Keep in this form to make sure we don't miss restoring any newly added
        # data. Make sure the order is correct
        self.cpu.PC, self.cpu._last_pc = checkpoint_data

    def execute(self):
        """
        Perform a single step on the current state
        """
        from manticore.native.cpu.abstractcpu import (
            ConcretizeRegister, ConcretizeMemory
        )  # must be here, otherwise we get circular imports

        checkpoint_data = CheckpointData(pc=self.cpu.PC, last_pc=self.cpu._last_pc)
        try:
            result = self._platform.execute()

        # Instead of State importing SymbolicRegisterException and SymbolicMemoryException
        # from cpu/memory shouldn't we import Concretize from linux, cpu, memory ??
        # We are forcing State to have abstractcpu
        except ConcretizeRegister as exc:
            # Need to define local variable to use in closure
            e = exc
            expression = self.cpu.read_register(e.reg_name)

            def setstate(state: State, value):
                state.cpu.write_register(e.reg_name, value)

            self._rollback(checkpoint_data)
            raise Concretize(str(e), expression=expression, setstate=setstate, policy=e.policy)
        except ConcretizeMemory as exc:
            # Need to define local variable to use in closure
            e = exc
            expression = self.cpu.read_int(e.address, e.size)

            def setstate(state: State, value):
                state.cpu.write_int(e.address, value, e.size)

            self._rollback(checkpoint_data)
            raise Concretize(str(e), expression=expression, setstate=setstate, policy=e.policy)
        except Concretize as e:
            self._rollback(checkpoint_data)
            raise e
        except MemoryException as e:
            raise TerminateState(str(e), testcase=True)

        # Remove when code gets stable?
        assert self.platform.constraints is self.constraints

        return result

coredump = sys.argv[1]

initial_state = StateNoOS(coredump)
SRAX = initial_state.constraints.new_bitvec(64, name="RAX")
initial_state.cpu.RAX = SRAX
initial_state.platform.cpu
m = ManticoreBase(initial_state)
m.run()
m.finalize()
lklkj
core = ELFFile(open(coredump, "rb"))
assert core.header.e_type == "ET_CORE"
for elf_segment in core.iter_segments():
    print(elf_segment.header.p_type)
##    if elf_segment.header.p_type != "PT_INTERP":
#        continue
#    self.interpreter = Elf(elf_segment.data()[:-1])
#    break


import pdb

pdb.set_trace()


constraints = ConstraintSet()
platform = linux.SLinux(
    program, argv=argv, envp=env, symbolic_files=symbolic_files, pure_symbolic=pure_symbolic
)
