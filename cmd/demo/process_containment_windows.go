//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	jobObjectInfoExtendedLimit   = 9
	jobObjectLimitKillOnJobClose = 0x2000
	processTerminate             = 0x0001
	processSetQuota              = 0x0100
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IOInfo                jobObjectIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	createJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	setInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	openProcess              = kernel32.NewProc("OpenProcess")
	assignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	closeKernelHandle        = kernel32.NewProc("CloseHandle")
)

func configureCommand(_ *exec.Cmd) error { return nil }

func containStartedProcess(process *os.Process) (func() error, error) {
	job, _, _ := createJobObjectW.Call(0, 0)
	if job == 0 {
		return nil, errors.New("job object creation failed")
	}
	closeJob := func() error {
		result, _, closeErr := closeKernelHandle.Call(job)
		if result == 0 {
			return closeErr
		}
		return nil
	}
	limits := jobObjectExtendedLimitInformation{}
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	result, _, setErr := setInformationJobObject.Call(
		job, jobObjectInfoExtendedLimit, uintptr(unsafe.Pointer(&limits)),
		unsafe.Sizeof(limits),
	)
	if result == 0 {
		_ = closeJob()
		return nil, setErr
	}
	processHandle, _, openErr := openProcess.Call(
		processTerminate|processSetQuota, 0, uintptr(uint32(process.Pid)),
	)
	if processHandle == 0 {
		_ = closeJob()
		return nil, openErr
	}
	defer closeKernelHandle.Call(processHandle)
	result, _, assignErr := assignProcessToJobObject.Call(job, processHandle)
	if result == 0 {
		_ = closeJob()
		return nil, assignErr
	}
	return closeJob, nil
}
