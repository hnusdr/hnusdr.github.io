---
layout:     post
title:      "Testing Secure SMMU in QEMU using OP-TEE and Hafnium"
subtitle:   "A comprehensive guide to enabling and testing Secure SMMU functionality in Hafnium hypervisor"
date:       2025-08-09
author:     "hnusdr"
header-img: "img/post-optee.png"
catalog: true
tags:
    - Hafnium
    - SMMU
    - OP-TEE
    - QEMU
    - ARM
    - Security
    - Hypervisor
---

# Testing Secure SMMU in QEMU using OP-TEE and Hafnium

The core purpose of this article is to provide a complete technical solution for testing a self-implemented Secure SMMU feature in QEMU. Hafnium supports both FVP and QEMU platforms. Since the standard version of QEMU lacks support for Secure SMMU, developers who implement or extend this functionality in QEMU can use the technical path detailed in this article to effectively test and verify their implementation using Hafnium.

This solution integrates OP-TEE, Hafnium, and QEMU to perform in-depth testing and verification of the SMMU Secure State functionality in the Arm architecture. Please note: [The Secure SMMU feature in QEMU is still in the RFC phase](https://lists.gnu.org/archive/html/qemu-arm/2025-08/msg00355.html) and has not been merged upstream. The code below uses this patch to test the Secure SMMU functionality.

## 1. Core Technical Components Overview

### Hafnium
Hafnium is an open-source reference Secure Partition Manager (SPM) for the Arm architecture, designed by Google. It adheres to and implements the Arm Secure Partition Client Interface (SPCI) specification, running at Exception Level 2 (EL2) to isolate and manage secure partitions in the Secure World.

### OP-TEE
As an open-source Trusted Execution Environment (TEE), OP-TEE is a widely used security solution in the Arm ecosystem. In this technical solution, it forms the foundation of the entire build system and the Secure Boot Chain.

### QEMU
QEMU is a powerful open-source machine emulator and virtualization platform. This solution utilizes its `virt` virtual platform for the Arm architecture, which has built-in support for full SMMUv3 emulation. An alternative to QEMU is Arm's FVP (Fixed Virtual Platforms). FVP provides complete emulation of Secure SMMU, but its support for devices like PCIe is not as comprehensive as QEMU's. QEMU is more mature in emulating PCIe and non-secure SMMU, but its standard version currently does not support Secure SMMU at all.

### Secure SMMU
This is a key feature of the Arm SMMU architecture that allows software running in the Secure World (such as Hafnium) to directly control and configure the SMMU. This functionality is crucial for achieving efficient isolation of Direct Memory Access (DMA) devices and protecting against DMA attacks from the non-secure world.

## 2. Research Goals and Methods

Hafnium's existing codebase already contains the core logic needed to initialize the SMMU and supports writing to Secure SMMU registers. However, this functionality is **inactive** in the default configuration.

The primary goal of this research is to activate and verify this functionality. This approach allows for the direct initialization of the SMMU during the early stages of the secure boot process (BL1 → BL2 → BL32/Hafnium). This path enables testing of the SMMU initialization code before entering the BL33 stage and loading a normal-world operating system (like the Linux kernel), thus achieving more efficient and targeted verification.

## 3. System Build Process

The system build process involves several key stages. Please follow the steps below to configure the environment and compile the required components.

### Phase 1: Environment and Repo Tool Configuration

```bash
# Create a local binary directory and add it to the system PATH variable
mkdir -p ~/.local/bin
PATH="${HOME}/.local/bin:${PATH}"

# Download the repo tool and make it executable
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.local/bin/repo
chmod a+rx ~/.local/bin/repo
```

### Phase 2: OP-TEE Project Initialization and Code Synchronization

```bash
# Create a working directory for the project
mkdir optee
cd optee

# Initialize the project repository based on the qemu_v8 manifest
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml

# Synchronize all repositories using multiple threads for efficiency
repo sync -j16
```

### Phase 3: Build Environment Configuration

All code modifications below are based on the default branch; no branch switching is performed in any repository.

#### Modify the `build` script
Enter the `build` directory. Before compiling, you must modify the following files to ensure correct Hafnium integration and enable the relevant features:

- `build/qemu_v8.mk`: 

```
diff --git a/qemu_v8.mk b/qemu_v8.mk
index 0589fd1..d13919b 100644
--- a/qemu_v8.mk
+++ b/qemu_v8.mk
@@ -61,7 +61,7 @@ endif
 # 3:   SPMC and SPMD at EL3 (in TF-A)
 # 2:   SPMC at S-EL2 (in Hafnium), SPMD at EL3 (in TF-A)
 # 1:   SPMC at S-EL1 (in OP-TEE), SPMD at EL3 (in TF-A)
-SPMC_AT_EL ?= n
+SPMC_AT_EL ?= 2
 ifneq ($(filter-out n 1 2 3,$(SPMC_AT_EL)),)
 $(error Unsupported SPMC_AT_EL value $(SPMC_AT_EL))
 endif
@@ -629,11 +629,11 @@ QEMU_RUN_ARGS += -s -S -serial tcp:127.0.0.1:$(QEMU_NW_PORT) -serial tcp:127.0.0
 .PHONY: run-only
 run-only:
        ln -sf $(ROOT)/out-br/images/rootfs.cpio.gz $(BINARIES_PATH)/
-       $(call check-terminal)
-       $(call run-help)
-       $(call launch-terminal,$(QEMU_NW_PORT),"Normal World")
-       $(call launch-terminal,$(QEMU_SW_PORT),"Secure World")
-       $(call wait-for-ports,$(QEMU_NW_PORT),$(QEMU_SW_PORT))
+#      $(call check-terminal)
+#      $(call run-help)
+#      $(call launch-terminal,$(QEMU_NW_PORT),"Normal World")
+#      $(call launch-terminal,$(QEMU_SW_PORT),"Secure World")
+#      $(call wait-for-ports,$(QEMU_NW_PORT),$(QEMU_SW_PORT))
        cd $(BINARIES_PATH) && $(QEMU_BIN) $(QEMU_RUN_ARGS)
 
 ifneq ($(filter check check-rust,$(MAKECMDGOALS)),)
```

- Change the value of `SPMC_AT_EL` from `n` to `2` to enable Hafnium to run at EL2.
- The code that enables the default GUI terminal is commented out to allow proper operation in a pure command-line environment (like a typical VSCode remote SSH development setup). Later, we will use the `-serial tcp:localhost:15000` parameter in QEMU to output logs, making the development process more flexible.


#### Start Building the Toolchain
After making the above changes, build the toolchain.

```bash
cd build
make -j16 toolchains
```

### Phase 4: Hafnium Setup and Source Code Modification

```bash
# Switch to the Hafnium source directory
cd ../hafnium

# Initialize and recursively update Hafnium's submodules
git submodule update --init --recursive

# Add the path to the Clang toolchain to the system PATH variable
# (Please update the path according to your actual setup)
export PATH="/path/to/your/clang/bin/:$PATH"
```

**Core Step:** This phase requires modifying the Hafnium source code to enable support for Secure SMMU. This modification involves several parts of the codebase.

#### Modify Hafnium build scripts and code
- `build/BUILD.gn`: 
Assuming the absolute path to hafnium is: `/mnt/sda1/phytium-tee-host/optee/hafnium/` 

```
diff --git a/build/BUILD.gn b/build/BUILD.gn
index 5903877..2a6988c 100644
--- a/build/BUILD.gn
+++ b/build/BUILD.gn
@@ -11,6 +11,7 @@ config("compiler_defaults") {
   cflags = [
     "-gdwarf-4",
     "-O2",
+    "-fdebug-prefix-map=../../=/mnt/sda1/phytium-tee-host/optee/hafnium/",
 
     "-Wall",
     "-Wextra",
```

-  `src/BUILD.gn`
**This is the most critical step to successfully enable the Secure SMMU feature in Hafnium!**

```
diff --git a/src/BUILD.gn b/src/BUILD.gn
index 406b4db..ad4be8b 100644
--- a/src/BUILD.gn
+++ b/src/BUILD.gn
@@ -37,9 +37,10 @@ source_set("src_not_testable_yet") {
     ":src_testable",
     "//project/${project}/${plat_name}",
     "//src/arch/${plat_arch}/hypervisor:other_world",
+    "//src/arch/aarch64/arm_smmuv3",
     plat_boot_flow,
     plat_console,
-    plat_iommu,
+    #plat_iommu,
   ]
 }
 
@@ -71,10 +72,11 @@ source_set("src_testable") {
     "//src/arch/${plat_arch}:arch",
     "//src/arch/${plat_arch}/hypervisor",
     "//src/arch/${plat_arch}/hypervisor:other_world",
+    "//src/arch/aarch64/arm_smmuv3",
     "//vmlib",
     plat_boot_flow,
     plat_console,
-    plat_iommu,
+    #plat_iommu,
     plat_memory_protect,
   ]
 }
```

- `src/arch/aarch64/arm_smmuv3/args.gni`
This sets the base address and size of the SMMU.

```
diff --git a/src/arch/aarch64/arm_smmuv3/args.gni b/src/arch/aarch64/arm_smmuv3/args.gni
index 942e2e9..6b5bb09 100644
--- a/src/arch/aarch64/arm_smmuv3/args.gni
+++ b/src/arch/aarch64/arm_smmuv3/args.gni
@@ -5,6 +5,6 @@
 # https://opensource.org/licenses/BSD-3-Clause.
 
 declare_args() {
-  smmu_base_address = ""
-  smmu_memory_size = ""
+  smmu_base_address = "0x09050000"
+  smmu_memory_size = "0x00020000"
 }
```


### Phase 5: Firmware Compilation

Return to the project's top-level `build` directory to perform the final firmware compilation.

```bash
cd ../build/
```

You can choose either of the following two compilation paths.

#### Compilation Path A: Minimal Test Build (without BL33)

This command generates the minimal firmware set required to run Hafnium and test SMMU initialization.

```bash
make hafnium arm-tf -j16 DEBUG=1
```

#### Compilation Path B: Full Boot Build with Linux (with BL33)

This process first builds the standard boot chain, then compiles Hafnium independently.

```bash
# The default build command does not include Hafnium
make -j16 DEBUG=1
```

##### Clean and Explicitly Compile Hafnium

```bash
make hafnium-clean # If previously compiled
make -j16 hafnium DEBUG=1
```
> **Note:** You can simplify the steps by modifying the project's Makefile to integrate the Hafnium compilation task into the default build process.

#### Check the Output Artifacts

```bash
# BL1
ls -l /mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl1/bl1.elf
ls -l /mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin

# BL2
ls -l /mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl2/bl2.elf

# BL32(Hafnium)
ls -l /mnt/sda1/phytium-tee-host/optee/hafnium/out/reference/secure_qemu_aarch64_clang/hafnium.elf
```

## 4. Execution and Debugging Plan

### QEMU Execution (Hafnium-only environment)

The following command starts the QEMU simulation environment, which loads the secure firmware and enables SMMUv3 emulation, but does not load the Linux kernel. Here, we trace all SMMU-related tracing points and output them to the `qemu.log` file.

```bash
./qemu-system-aarch64 -d trace:help | grep smmu > smmu-events.txt

# Run QEMU
./qemu-system-aarch64 \
    -machine virt,acpi=off,secure=on,mte=on,gic-version=3,virtualization=true,iommu=smmuv3 \
    -smp 1 \
    -cpu max,sme=on,pauth-impdef=on \
    -m 3072 \
    -d guest_errors,unimp,invalid_mem \
    -trace events=/mnt/sda1/phytium-tee-host/qemu/smmu-events.txt \
    -qmp unix:/tmp/qmp-sock13,server=on,wait=off \
    -nographic \
    -serial tcp:localhost:15000 \
    -serial tcp:localhost:15001 \
    -bios /mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin \
    -semihosting-config enable=on,target=native \
    -monitor stdio \
    -D /mnt/sda1/phytium-tee-host/qemu/qemu.log
```

- TCP port `15000` is used for Normal World logs, and port `15001` is for Secure World logs.
- `/mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin` is the path to the BL1 firmware obtained above; BL1 will automatically load subsequent stages like BL2/BL32.
- The `semihosting-config` feature is used to get serial output during the Hafnium startup phase.

### GDB Debugging with VSCode

To debug the firmware stack, add the `-S -s` flags when starting QEMU to make it pause and wait for a GDB client connection. Then, you can use the following `launch.json` configuration in VSCode for debugging. This configuration loads the symbol files for each firmware stage at their respective memory-loaded addresses.

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Firmware Debug",
            "type": "cppdbg",
            "request": "launch",
            "program": "/mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl1/bl1.elf",
            "miDebuggerServerAddress": "localhost:1234",
            "miDebuggerPath": "/usr/bin/gdb-multiarch",
            "cwd": "/mnt/sda1/phytium-tee-host/optee-qemu",
            "stopAtEntry": true,
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Set architecture to aarch64",
                    "text": "set architecture aarch64",
                    "ignoreFailures": true
                },
                {
                    "text": "add-symbol-file /mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl2/bl2.elf 0xe05b000"
                },
                {
                    "text": "add-symbol-file /mnt/sda1/phytium-tee-host/optee/hafnium/out/reference/secure_qemu_aarch64_clang/hafnium.elf 0xe100000"
                }
            ]
        }
    ]
}
```

Of course, you can also co-debug the secure firmware and QEMU. The `launch.json` file for QEMU is as follows:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "QEMU Secure SMMU Debug",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/build-debug/qemu-system-aarch64",
            "args": [
                "-machine", "virt,acpi=off,secure=on,mte=on,gic-version=3,virtualization=true,iommu=smmuv3",
                "-smp", "1",
                "-cpu", "max,sme=on,pauth-impdef=on",
                "-m", "3072",
                "-d", "guest_errors,unimp,invalid_mem",
                "-trace", "events=/mnt/sda1/phytium-tee-host/qemu/smmu-events.txt",
                "-qmp", "unix:/tmp/qmp-sock13,server=on,wait=off",
                "-nographic",
                "-serial", "tcp:localhost:15000",
                "-serial", "tcp:localhost:15001",
                "-bios", "/mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin",
                "-semihosting-config", "enable=on,target=native",
                "-monitor", "stdio",
                "-D", "/mnt/sda1/phytium-tee-host/qemu/qemu.log",
                "-S", "-s"
            ],
            "cwd": "${workspaceFolder}",
            "stopAtEntry": false,
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerPath": "/usr/bin/gdb-multiarch"
        }
    ]
}
```


If you need to load the Linux kernel, you must modify the QEMU command-line arguments accordingly to specify the paths for the kernel image, RAM disk. To debug with the default OP-TEE build artifacts, add the following parameters:

```json
"-kernel", "/mnt/sda1/phytium-tee-host/optee/out/bin/Image",
"-initrd", "/mnt/sda1/phytium-tee-host/optee/out/bin/rootfs.cpio.gz",
"-append", "console=ttyAMA0,38400 keep_bootcon root=/dev/vda2",
```



### Execution Results
From the `qemu.log` generated by running QEMU, you can see a large number of writes to secure registers with offsets greater than 0x8000:
```
smmu_add_mr smmuv3-iommu-memory-region-1-0
smmu_add_mr smmuv3-iommu-memory-region-0-0
smmu_add_mr smmuv3-iommu-memory-region-8-1
smmu_reset_exit 
smmuv3_write_mmio addr: 0x8044 val:0x80000000 size: 0x4(0)
smmuv3_read_mmio addr: 0x8044 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8020 val:0x0 size: 0x4(0)
smmuv3_write_mmio addr: 0x8020 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8024 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x1c val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x0 val:0xd44101b size: 0x4(0)
smmuv3_read_mmio addr: 0x8004 val:0xa0000005 size: 0x4(0)
smmuv3_read_mmio addr: 0x14 val:0x74 size: 0x4(0)
smmuv3_write_mmio addr: 0x8028 val:0xd75 size: 0x4(0)
smmuv3_read_mmio addr: 0x802c val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x4 val:0x14a0005 size: 0x4(0)
smmuv3_read_mmio addr: 0x8004 val:0xa0000005 size: 0x4(0)
smmuv3_write_mmio addr: 0x8090 val:0x400000000e14e00a size: 0x8(0)
smmuv3_write_mmio addr: 0x809c val:0x0 size: 0x4(0)
smmuv3_write_mmio addr: 0x8098 val:0x0 size: 0x4(0)
smmuv3_write_mmio addr: 0x80a0 val:0x400000000e15300a size: 0x8(0)
smmuv3_write_mmio addr: 0x80a8 val:0x0 size: 0x4(0)
smmuv3_write_mmio addr: 0x80ac val:0x0 size: 0x4(0)
smmuv3_write_mmio addr: 0x8088 val:0x5 size: 0x4(0)
smmuv3_write_mmio addr: 0x8080 val:0x400000000e15c000 size: 0x8(0)
smmuv3_read_mmio addr: 0x8020 val:0x0 size: 0x4(0)
smmuv3_cmdq_consume_out prod:0, cons:0, prod_wrap:0, cons_wrap:0 
smmuv3_write_mmio addr: 0x8020 val:0x8 size: 0x4(0)
smmuv3_read_mmio addr: 0x8024 val:0x8 size: 0x4(0)
smmuv3_cmdq_consume_out prod:0, cons:0, prod_wrap:0, cons_wrap:0 
smmuv3_write_mmio addr: 0x8020 val:0xc size: 0x4(0)
smmuv3_read_mmio addr: 0x8024 val:0xc size: 0x4(0)
smmuv3_invalidate_all_caches Invalidate all SMMU caches and TLBs
smmu_iotlb_inv_all IOTLB invalidate all
smmuv3_write_mmio addr: 0x803c val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x803c val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8098 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x809c val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8060 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8064 val:0x0 size: 0x4(0)
smmuv3_cmdq_consume prod=1 cons=0 prod.wrap=0 cons.wrap=0 is_secure_cmdq=1
smmuv3_cmdq_opcode <--- SMMU_CMD_CFGI_STE_RANGE
smmuv3_cmdq_cfgi_ste_range start=0x0 - end=0xffffffff
smmu_configs_inv_sid_range Config cache INV SID range from 0x0 to 0xffffffff
smmuv3_cmdq_consume_out prod:1, cons:1, prod_wrap:0, cons_wrap:0 
smmuv3_write_mmio addr: 0x8098 val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x8098 val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x8098 val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x809c val:0x1 size: 0x4(0)
smmuv3_read_mmio addr: 0x8060 val:0x0 size: 0x4(0)
smmuv3_read_mmio addr: 0x8064 val:0x0 size: 0x4(0)
smmuv3_cmdq_consume prod=2 cons=1 prod.wrap=0 cons.wrap=0 is_secure_cmdq=1
smmuv3_cmdq_opcode <--- SMMU_CMD_CFGI_STE_RANGE
smmuv3_cmdq_cfgi_ste_range start=0x0 - end=0xffffffff
smmu_configs_inv_sid_range Config cache INV SID range from 0x0 to 0xffffffff
smmuv3_cmdq_consume_out prod:2, cons:2, prod_wrap:0, cons_wrap:0 
smmuv3_write_mmio addr: 0x8098 val:0x2 size: 0x4(0)
smmuv3_read_mmio addr: 0x8098 val:0x2 size: 0x4(0)
smmuv3_read_mmio addr: 0x8098 val:0x2 size: 0x4(0)
smmuv3_read_mmio addr: 0x809c val:0x2 size: 0x4(0)
smmuv3_cmdq_consume_out prod:2, cons:2, prod_wrap:0, cons_wrap:0 
smmuv3_write_mmio addr: 0x8020 val:0xd size: 0x4(0)
smmuv3_read_mmio addr: 0x8024 val:0xd size: 0x4(0)

```

## 5. Conclusion and Limitations

The method described in this article can effectively verify Hafnium's ability to correctly initialize the SMMU and configure its secure registers. However, this method does not provide a mechanism to test the core functionality of the SMMU, which is the address translation process for DMA transactions.

Therefore, testing the address translation process without booting a full Linux kernel requires a different technical approach. The related methods will be detailed in a subsequent research report.