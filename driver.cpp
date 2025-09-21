#include <ntifs.h>
#include <windef.h>

extern "C" {
#include <intrin.h>
}
#pragma intrinsic(__readcr3)

UNICODE_STRING devName, symLink;

typedef struct _POOL_REC {
	PVOID base;
	ULONG_PTR nonPaged : 1;
	ULONG_PTR length;
	UCHAR label[4];
} POOL_REC, * PPOOL_REC;

typedef struct _POOL_DATA {
	ULONG numEntries;
	POOL_REC records[1];
} POOL_DATA, * PPOOL_DATA;

typedef enum _SYS_QUERY {
	SystemPoolInfo = 0x42,
} SYS_QUERY;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYS_QUERY, PVOID, ULONG, PULONG);

#define IOCTL_MEM_RW       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_PROC_BASE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_POOL_SCAN    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7F3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define AUTH_KEY           0xC4B9E2A1

#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000
static const UINT64 PAGE_MASK = (~0xFULL << 8) & 0xFFFFFFFFFULL;

typedef struct {
	INT32 auth;
	INT32 procId;
	ULONGLONG vAddr;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN isWrite;
} MEM_RW, * PMEM_RW;

typedef struct {
	INT32 auth;
	INT32 procId;
	ULONGLONG* result;
} PROC_BASE, * PPROC_BASE;

typedef struct {
	INT32 auth;
	ULONGLONG* result;
} POOL_SCAN, * PPOOL_SCAN;

#define CACHE_SIZE 512

struct PageCache {
	UINT64 virtPage;
	UINT64 physPage;
};

static PageCache g_pageCache[CACHE_SIZE] = {};

__forceinline int GetCacheSlot(UINT64 virtPage) {
	return (int)(virtPage % CACHE_SIZE);
}

__forceinline NTSTATUS ReadPhysical(PVOID physAddr, PVOID out, SIZE_T len, SIZE_T* transferred) {
	MM_COPY_ADDRESS mm = { .PhysicalAddress.QuadPart = (LONGLONG)physAddr };
	return MmCopyMemory(out, mm, len, MM_COPY_MEMORY_PHYSICAL, transferred);
}

__forceinline NTSTATUS WritePhysical(PVOID physAddr, PVOID in, SIZE_T len, SIZE_T* transferred) {
	if (!physAddr) return STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS pa = { .QuadPart = (LONGLONG)physAddr };
	PVOID mapped = MmMapIoSpaceEx(pa, len, PAGE_READWRITE);
	if (!mapped) return STATUS_UNSUCCESSFUL;
	RtlCopyMemory(mapped, in, len);
	*transferred = len;
	MmUnmapIoSpace(mapped, len);
	return STATUS_SUCCESS;
}

__forceinline INT32 LocateCr3Offset() {
	PEPROCESS proc = PsGetCurrentProcess();
	if (!proc) return 0;
	ULONG_PTR cr3 = __readcr3() & ~0xFULL;
	PUCHAR base = (PUCHAR)proc;
	for (int i = 0; i < 0x600; i += sizeof(ULONG_PTR)) {
		if ((*(PULONG_PTR)(base + i) & ~0xFULL) == cr3) {
			return i;
		}
	}
	return 0x2F0;
}

__forceinline UINT64 FetchCr3(PEPROCESS proc) {
	PUCHAR ptr = (PUCHAR)proc;
	ULONG_PTR val = *(PULONG_PTR)(ptr + 0x30);
	if (!val) val = *(PULONG_PTR)(ptr + LocateCr3Offset());
	return val;
}

__forceinline UINT64 MapVirtToPhys(UINT64 cr3, UINT64 va) {
	UINT64 virtPage = va >> 12;
	int slot = GetCacheSlot(virtPage);
	auto& cache = g_pageCache[slot];

	if (cache.virtPage == virtPage) {
		return cache.physPage + (va & 0xFFF);
	}

	cr3 &= ~0xFULL;
	UINT64 offset = va & 0xFFF;
	UINT64 pteIdx = (va >> 12) & 0x1FF;
	UINT64 ptIdx = (va >> 21) & 0x1FF;
	UINT64 pdIdx = (va >> 30) & 0x1FF;
	UINT64 pdpIdx = (va >> 39) & 0x1FF;

	UINT64 entry = 0;
	SIZE_T read = 0;

#define READ_PHYS(addr) \
	if (!NT_SUCCESS(ReadPhysical((PVOID)(addr), &entry, 8, &read)) || !(entry & 1)) return 0;

	READ_PHYS(cr3 + 8 * pdpIdx);
	READ_PHYS((entry & PAGE_MASK) + 8 * pdIdx);
	if (entry & (1ULL << 7)) {
		UINT64 physBase = (entry & (~0ULL << 42 >> 12));
		cache.virtPage = virtPage;
		cache.physPage = physBase;
		return physBase + (va & ~(~0ULL << 30));
	}
	READ_PHYS((entry & PAGE_MASK) + 8 * ptIdx);
	if (entry & (1ULL << 7)) {
		UINT64 physBase = (entry & PAGE_MASK);
		cache.virtPage = virtPage;
		cache.physPage = physBase;
		return physBase + (va & ~(~0ULL << 21));
	}
	READ_PHYS((entry & PAGE_MASK) + 8 * pteIdx);
	UINT64 physBase = (entry & PAGE_MASK);
	cache.virtPage = virtPage;
	cache.physPage = physBase;
	return physBase + offset;
}

__forceinline NTSTATUS ProcessMemRW(PMEM_RW req) {
	if (!req || req->auth != AUTH_KEY || !req->procId || !req->size) return STATUS_UNSUCCESSFUL;

	PEPROCESS proc = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->procId, &proc))) return STATUS_UNSUCCESSFUL;

	UINT64 cr3 = FetchCr3(proc);
	ObDereferenceObject(proc);

	SIZE_T total = 0, toMove = 0, remaining = (SIZE_T)req->size;
	UINT64 virtAddr = req->vAddr, bufAddr = req->buffer;

	while (remaining > 0) {
		UINT64 physAddr = MapVirtToPhys(cr3, virtAddr);
		if (!physAddr) break;

		SIZE_T pageOffset = physAddr & 0xFFF;
		toMove = (remaining < (PAGE_SIZE - pageOffset)) ? remaining : (PAGE_SIZE - pageOffset);

		NTSTATUS status = req->isWrite ?
			WritePhysical((PVOID)physAddr, (PVOID)(UINT_PTR)bufAddr, toMove, &toMove) :
			ReadPhysical((PVOID)physAddr, (PVOID)(UINT_PTR)bufAddr, toMove, &toMove);
		if (!NT_SUCCESS(status)) return status;

		virtAddr += toMove;
		bufAddr += toMove;
		remaining -= toMove;
		total += toMove;
	}

	return total == req->size ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

__forceinline NTSTATUS ProcessBaseAddr(PPROC_BASE req) {
	if (!req || req->auth != AUTH_KEY || !req->procId) return STATUS_UNSUCCESSFUL;

	PEPROCESS proc = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->procId, &proc))) return STATUS_UNSUCCESSFUL;

	ULONGLONG base = (ULONGLONG)PsGetProcessSectionBaseAddress(proc);
	RtlCopyMemory(req->result, &base, sizeof(base));
	ObDereferenceObject(proc);
	return STATUS_SUCCESS;
}

__forceinline NTSTATUS ScanPool(PPOOL_SCAN req) {
	if (!req || req->auth != AUTH_KEY) return STATUS_UNSUCCESSFUL;

	ULONG size = 0;
	ZwQuerySystemInformation(SystemPoolInfo, &size, 0, &size);

	PPOOL_DATA pool = (PPOOL_DATA)ExAllocatePool(NonPagedPool, size);
	if (!pool) return STATUS_INSUFFICIENT_RESOURCES;

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemPoolInfo, pool, size, &size))) {
		ExFreePool(pool);
		return STATUS_UNSUCCESSFUL;
	}

	for (ULONG i = 0; i < pool->numEntries; ++i) {
		PPOOL_REC rec = &pool->records[i];
		if (rec->nonPaged && rec->length == 0x200000 && *(ULONG*)rec->label == 'XzTq') {
			*req->result = (ULONGLONG)rec->base;
			ExFreePool(pool);
			return STATUS_SUCCESS;
		}
	}

	ExFreePool(pool);
	return STATUS_NOT_FOUND;
}

NTSTATUS HandleIoctl(PDEVICE_OBJECT, PIRP irp) {
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	PVOID buffer = irp->AssociatedIrp.SystemBuffer;
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG inSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG outSize = 0;

	switch (code) {
	case IOCTL_MEM_RW:
		if (inSize == sizeof(MEM_RW)) {
			status = ProcessMemRW((PMEM_RW)buffer);
			outSize = sizeof(MEM_RW);
		}
		break;
	case IOCTL_PROC_BASE:
		if (inSize == sizeof(PROC_BASE)) {
			status = ProcessBaseAddr((PPROC_BASE)buffer);
			outSize = sizeof(PROC_BASE);
		}
		break;
	case IOCTL_POOL_SCAN:
		if (inSize == sizeof(POOL_SCAN)) {
			status = ScanPool((PPOOL_SCAN)buffer);
			outSize = sizeof(POOL_SCAN);
		}
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = outSize;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS Unsupported(PDEVICE_OBJECT, PIRP irp) {
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS PassThrough(PDEVICE_OBJECT, PIRP irp) {
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

void DriverUnload(PDRIVER_OBJECT drv) {
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS DriverInit(PDRIVER_OBJECT drv, PUNICODE_STRING) {
	RtlInitUnicodeString(&devName, L"\\Device\\k9mPq3vL7x");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\k9mPq3vL7x");

	PDEVICE_OBJECT device = nullptr;
	NTSTATUS status = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
	if (!NT_SUCCESS(status)) return status;

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(device);
		return status;
	}

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv->MajorFunction[i] = Unsupported;

	drv->MajorFunction[IRP_MJ_CREATE] = PassThrough;
	drv->MajorFunction[IRP_MJ_CLOSE] = PassThrough;
	drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctl;
	drv->DriverUnload = DriverUnload;

	device->Flags |= DO_BUFFERED_IO;
	device->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath) {
	UNREFERENCED_PARAMETER(regPath);
	return IoCreateDriver(nullptr, DriverInit);
}
