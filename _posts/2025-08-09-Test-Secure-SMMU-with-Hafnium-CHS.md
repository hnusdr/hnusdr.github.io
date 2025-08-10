---
layout:     post
title:      "在QEMU中利用OP-TEE与Hafnium对QEMU Secure SMMU进行测试"
subtitle:   ""
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

# 在QEMU中利用OP-TEE与Hafnium对QEMU Secure SMMU进行测试

本文的核心宗旨在于提供一套完整的技术方案，用以测试在QEMU中自行实现的Secure SMMU功能。Hafnium本身可同时支持FVP与QEMU两种平台。鉴于QEMU在标准版本中缺乏对Secure SMMU的支持，当开发者在QEMU中自行实现或扩展了Secure SMMU功能后，便可采用本文所详述的技术路径，利用Hafnium对其实现进行有效的功能性测试与验证。

本方案通过集成OP-TEE、Hafnium及QEMU，旨在实现对ARM架构下SMMU Secure State 功能的深度测试与验证。请注意：[QEMU中的Secure SMMU功能仍在RFC中](https://lists.gnu.org/archive/html/qemu-arm/2025-08/msg00355.html)，并未合入upstream，下面代码是使用了该补丁来测试的Secure SMMU功能。

## 1. 核心技术组件概述

### Hafnium
此为谷歌公司为Arm架构设计的开源参考安全分区管理器（SPM）。它遵循并实现了Arm安全分区客户端接口（SPCI）规范，运行于异常级别2（EL2），负责对安全世界（Secure World）中的安全分区进行隔离与管理。

### OP-TEE
作为一个开源的可信执行环境（TEE），OP-TEE是Arm生态系统中广泛应用的安全解决方案。在本技术方案中，它构成了整个构建体系及安全启动链（Secure Boot Chain）的基础。

### QEMU
QEMU是一款功能强大的开源机器级模拟器与虚拟化平台。本方案将利用其为Arm架构提供的virt虚拟平台，该平台内建了对SMMUv3的完整模拟支持。与QEMU相对应的是Arm的FVP（Fixed Virtual Platforms）。FVP能够提供对Secure SMMU的完整模拟，但在PCIe等设备的支持上不如QEMU完善。QEMU在PCIe和非安全SMMU的模拟方面更为成熟，但其标准版本目前完全不支持Secure SMMU。

### Secure SMMU
此为Arm SMMU架构的一项关键特性，它授权在安全世界中运行的软件（例如Hafnium）对SMMU进行直接控制与配置。该功能对于实现对直接内存访问（DMA）设备的高效隔离，并抵御来自非安全世界的DMA攻击，具有至关重要的作用。

## 2. 研究目标与方法

Hafnium的现有代码库已具备初始化SMMU所需的核心逻辑，并支持对Secure SMMU寄存器的写操作。然而，该功能在默认配置下处于**非激活状态**。

本研究的核心目标在于激活并验证此项功能。通过该方法，将能够在固件安全启动流程（BL1 → BL2 → BL32/Hafnium）的早期阶段直接完成对SMMU的初始化。此路径使得SMMU初始化代码的测试得以在进入BL33阶段并加载普通世界操作系统（如Linux内核）之前完成，从而实现了更高效、更具针对性的验证。

## 3. 系统构建流程

系统的构建过程包含以下几个关键阶段，请遵循相应步骤以配置环境并编译所需组件。

### 阶段一：环境与repo工具配置

```bash
# 创建一个本地二进制目录并将其添加至系统PATH变量
mkdir -p ~/.local/bin
PATH="${HOME}/.local/bin:${PATH}"

# 下载并赋予repo工具可执行权限
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.local/bin/repo
chmod a+rx ~/.local/bin/repo
```

### 阶段二：OP-TEE项目初始化与代码同步

```bash
# 为项目创建工作目录
mkdir optee
cd optee

# 依据qemu_v8 manifest初始化项目仓库
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml

# 采用多线程模式同步所有仓库以提升效率
repo sync -j16
```

### 阶段三：编译环境配置

以下所有代码的修改均基于默认分支，没有在任何仓库中进行过分支切换操作。

#### 修改 build 构建脚本
进入build目录。在执行编译前，必须对下列文件进行修改，以确保Hafnium的正确集成并启用相关功能：

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

- 这里需要将SPMC_AT_EL的值从n改为2，以启用Hafnium在EL2中运行。
- 另外将启用默认GUI终端的代码注释掉，是为了在纯命令行环境下（如常用的VSCode remote SSH开发环境下）正常工作。后面会结合QEMU中的 `-serial tcp:localhost:15000` 参数来输出日志，这样会使得开发方式更加灵活。


#### 开始构建工具链
完成上述修改后，执行工具链的构建。

```bash
cd build
make -j16 toolchains
```

### 阶段四：Hafnium设置与源码修改

```bash
# 切换至Hafnium源码目录
cd ../hafnium

# 初始化并递归更新Hafnium的子模块
git submodule update --init --recursive

# 将Clang工具链的路径添加至系统PATH变量
# (请根据实际路径进行更新)
export PATH="/path/to/your/clang/bin/:$PATH"
```

**核心步骤：** 此阶段要求对Hafnium源代码进行修改，以启用对安全SMMU的支持。此项修改涉及代码库中的多个部分。

#### 修改 hafnium 构建脚本和代码
- `build/BUILD.gn` : 
假设hafnium所在绝对路径为: `/mnt/sda1/phytium-tee-host/optee/hafnium/` 

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
**这是成功开启Hafnium中Secure SMMU功能最关键的一步！**

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
这给定了SMMU的基地址和大小。

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


### 阶段五：固件编译

返回项目顶层build目录以执行最终的固件编译。

```bash
cd ../build/
```

以下两种编译路径任选一个即可。

#### 编译路径A：最小化测试构建 (不含BL33)

此命令将生成运行Hafnium并测试SMMU初始化所需的最简化固件集。

```bash
make hafnium arm-tf -j16 DEBUG=1
```

#### 编译路径B：包含Linux的完整启动构建 (含BL33)

此流程首先构建标准的启动链，随后独立编译Hafnium。

```bash
# 默认编译命令不包含Hafnium
make -j16 DEBUG=1

```

##### 清理并显式编译Hafnium

```bash
make hafnium-clean # 如果之前有编译
make -j16 hafnium DEBUG=1
```
> **注：** 可通过修改项目的Makefile文件，将Hafnium的编译任务整合至默认构建流程中，从而简化操作步骤。

#### 检查输出产物

```bash
# BL1
ls -l /mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl1/bl1.elf
ls -l /mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin

# BL2
ls -l /mnt/sda1/phytium-tee-host/optee/trusted-firmware-a/build/qemu/debug/bl2/bl2.elf

# BL32(Hafnium)
ls -l /mnt/sda1/phytium-tee-host/optee/hafnium/out/reference/secure_qemu_aarch64_clang/hafnium.elf

```

## 4. 执行与调试方案

### QEMU执行 (仅Hafnium环境)

以下命令用于启动QEMU仿真环境，该环境加载了安全固件并启用了SMMUv3模拟，但未加载Linux内核。这里我们对所有smmu相关的tracing points进行了追踪，并输出到qemu.log文件中。

```bash
./qemu-system-aarch64 -d trace:help | grep smmu > smmu-events.txt

# 运行QEMU
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

- TCP 15000端口用于输出Normal world的日志，15001端口用于输出Secure world的日志。
- `/mnt/sda1/phytium-tee-host/optee/out/bin/bl1.bin ` 为上面获取的BL1固件的路径，BL1里会自动去加载BL2/BL32等后续阶段；
- semihosting-config 特性用于在Hafnium启动阶段获取串口输出。

### 基于VSCode的GDB调试

为对固件堆栈进行调试，需在启动QEMU时附加`-S -s`标志，以使其暂停并等待GDB客户端连接。随后，可利用VSCode中的以下`launch.json`配置进行调试。该配置能够在固件各阶段的内存加载地址处加载对应的符号文件。

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

当然，你也可以对安全固件与QEMU一起进行联合调试，QEMU侧的launch.json文件如下：

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


若需加载Linux内核，则必须相应地修改QEMU的命令行参数，以指定内核镜像、RAM disk文件的路径。如使用OP-TEE默认的编译产物调试则增加如下参数：

```json
"-kernel", "/mnt/sda1/phytium-tee-host/optee/out/bin/Image",
"-initrd", "/mnt/sda1/phytium-tee-host/optee/out/bin/rootfs.cpio.gz",
"-append", "console=ttyAMA0,38400 keep_bootcon root=/dev/vda2",
```



### 执行结果
可以从QEMU运行的qemu.log中看到发生了大量的偏移在0x8000之后的安全寄存器被写入的行为：
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

## 5. 本文总结与局限性

本文所阐述的方法能够有效验证Hafnium正确初始化SMMU并配置其安全寄存器的能力。然而，该方法并未提供一种机制来测试SMMU的核心功能，即DMA事务的地址转换流程。

因此，在不启动完整Linux内核的条件下对地址转换流程进行测试，需要采用一种不同的技术路径。相关方法将在后续的研究报告中进行详细介绍。