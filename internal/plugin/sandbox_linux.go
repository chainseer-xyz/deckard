//go:build linux && (amd64 || arm64)

package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func platformSandboxCommand(ctx context.Context, argv []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := append([]string{sandboxHelper}, argv...)
	return exec.CommandContext(ctx, self, args...), nil // #nosec G204 -- private re-exec installs seccomp before operator-configured argv
}

func runSandboxHelper(argv []string) error {
	// exec inherits the calling thread's seccomp filter. Lock the thread so
	// Go cannot move the exec syscall to an unfiltered thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
	}
	if runtime.GOARCH == "amd64" {
		// x32 shares AUDIT_ARCH_X86_64 but has a different syscall table.
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS})
	}
	for _, call := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_SENDTO, unix.SYS_SENDMSG, unix.SYS_SENDMMSG,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER} {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: call},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("plugin sandbox: no_new_privs: %w", err)
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]} // #nosec G115 -- fixed bounded filter has fewer than 40 instructions
	// The kernel copies this bounded BPF program synchronously before return.
	_, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&program)), 0, 0, 0) // #nosec G103 -- kernel ABI requires a pointer to SockFprog
	runtime.KeepAlive(filter)
	if errno != 0 {
		return fmt.Errorf("plugin sandbox: seccomp: %w", errno)
	}
	return unix.Exec(argv[0], argv, os.Environ())
}
