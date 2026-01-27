# Thesis-Kernel-Modules

## Overview

This repository contains the **guest-side components** of an experimental hypervisor-based monitoring system developed as part of a master thesis.

The system is designed under a **strong attacker model**: after an initial trusted bootstrap phase, the Linux guest is assumed to be **fully compromised**, including **kernel-level (root) privileges**. As a result, the guest kernel cannot be trusted to cooperate with the monitoring logic, nor to host any persistent monitoring component.

The monitoring approach implemented in this project explicitly avoids:
- persistent in-guest agents,
- guest-managed page tables or stacks,
- guest-visible memory hotplug or devices,
- reliance on kernel runtime services after bootstrap.

Instead, monitoring is performed through **short-lived execution windows** fully controlled by the hypervisor. During each window, a small payload is executed in kernel mode using:
- **hypervisor-owned page tables**,
- **host-private memory regions** exposed only via temporary EPT mappings,
- and a controlled CPU context switch managed by QEMU/KVM.

After the trusted bootstrap phase completes, no monitoring code or memory remains persistently visible inside the guest. All subsequent observation is performed as if the guest kernel were actively hostile.

This repository provides:
- a one-shot guest kernel module executed during the trusted bootstrap phase,   responsible for extracting and transmitting kernel layout metadata to the   hypervisor;
- the assembly payload executed during monitoring windows;
- scripts to build, integrate, and deploy the guest-side components required   by the system.



## Dependencies

This repository is part of a multi-repository setup. The components below are required to build and run the full system.

### Required repositories

- **QEMU (custom fork)**  
  This project depends on a modified QEMU/KVM implementation that provides:
  - the `fx` device,
  - the KVM-side takeover logic,
  - the host-private execution window based on temporary memslots and shadow page tables.

  Repository:  
  https://github.com/contisimone99/qemu

  > **Important:**  
  > The QEMU repository **must be located at `~/qemu`** on the filesystem.
  > The provided scripts assume this exact path.  
  > If QEMU is placed elsewhere, `runall.sh` and the payload build scripts will fail.

- **Linux kernel (guest)**  
  The guest kernel is provided as a **git submodule** of this repository and is built   from a custom fork of the official Linux kernel.

  Repository:  
  https://github.com/contisimone99/linux

  The guest kernel and the guest module **must match**:
  the bootstrap module extracts and sends kernel-specific metadata (e.g. `init_task`,   structure offsets), which are valid only for the exact kernel build used at runtime.

### This repository

- **Thesis-Kernel-Modules**  
  This repository contains:
  - the guest bootstrap kernel module (one-shot),
  - the assembly payload executed during the monitoring window,
  - scripts to compile the payload and inject it into QEMU,
  - scripts to prepare the guest filesystem and guest image,
  - the `runall.sh` script used to launch the full setup.

### Payload build and QEMU integration

The payload is compiled and then **directly patched into the QEMU source tree**.

In particular:
- the payload build script expects the QEMU repository to be located at `~/qemu`,
- it patches the `fx.c` device source at:

`~/qemu/hw/misc/fx.c`


### Runtime assumptions

`runall.sh` assumes:
- the QEMU repository is located at `~/qemu`,
- QEMU has already been built from that directory,
- the guest kernel image (`bzImage`) is present in the expected location.

Deviating from this layout requires manual modification of the scripts.


## Scripts overview

This repository provides several helper scripts used to build and run the experimental setup. These scripts assume that all required repositories have already been cloned in the expected locations.

- `compile_payload.sh`  
  Compiles the assembly payload and **injects it directly into the QEMU source   tree**, patching the `fx` device implementation.  
  This script assumes that the QEMU repository is located at `~/qemu` and that   the file `~/qemu/hw/misc/fx.c` is present.  
  It must be executed **after** cloning the QEMU repository and **before**   building QEMU.

- `create-debianImg.sh`  
  Creates or prepares the Debian-based guest disk image used for the experiments.
  This script is typically executed once, unless the guest filesystem layout   needs to be regenerated.

- `fx-boot.sh`  
  A **one-shot bootstrap script executed inside the guest during system   initialization**.  
  This script is **not meant to be executed manually** by the user.

  It is automatically injected into the guest filesystem by `runall.sh` and   executed via a systemd unit during early boot. Its responsibilities are:
  - loading the guest bootstrap kernel module to transmit trusted kernel     metadata to the hypervisor;
  - removing the kernel module immediately after execution;
  - deleting all related artifacts from disk (kernel module, systemd unit);
  - self-removal after completion.

  After this script finishes, no persistent monitoring component remains inside   the guest.

- `runall.sh`  
  Acts as the main entry point for running the system.  
  It prepares the guest filesystem by injecting the bootstrap kernel module,   the `fx-boot.sh` script, and the corresponding systemd unit, then launches   QEMU with the correct configuration.

  This script assumes that:
  - the QEMU repository is located at `~/qemu`,
  - QEMU has already been built,
  - the guest kernel image (`bzImage`) is available in the expected location.


## Prepare the system
This section describes the steps required to build all components of the system and assemble the experimental setup, starting from the guest kernel and ending with the execution of the full QEMU-based environment.

### Prepare Linux subdirectory

The guest Linux kernel is built from the provided submodule and must be compiled before any guest-side components, as both the bootstrap module and the monitoring payload depend on kernel-specific layout information.

Add the submodule to the repo
```sh
    git submodule update --init --recursive
```

Inside the repo you should see the following branch:

```sh
    guest-6.6
```

Now prepare all the headers (the last 2 command will take some time to complete)
```sh
    cd linux 

    # 1. complete cleanup
    make mrproper

    # 2. generate x86_64 config
    make x86_64_defconfig

    # 3. prepare necessary file for build
    make prepare

    # 4. prepare environment to compile modules
    make modules_prepare

    # 5. compile kernel image (bzImage)
    make -j"$(nproc)" bzImage

    # 6. compile kernel modules
    make -j"$(nproc)" modules
```
### Build the guest bootstrap kernel module

After building the guest kernel, compile the guest bootstrap kernel module.
The module must be built against the same kernel sources used to generate the `bzImage`.

```sh
cd fx-module
make
````

The resulting `.ko` file will later be injected into the guest filesystem during the bootstrap phase.

---

### Build and integrate the payload into QEMU

The monitoring payload must be compiled and injected into the QEMU source tree *before* building QEMU.

From the root of this repository:

```sh
./compile_payload.sh
```

This script:

* compiles the assembly payload,
* patches the `fx` device source file located at:

```text
~/qemu/hw/misc/fx.c
```

The QEMU repository **must** be located at `~/qemu`, otherwise this step will fail.

---

### Build QEMU (custom fork)

After the payload has been injected, QEMU must be built from the modified source tree.

```sh
cd ~/qemu
make -j"$(nproc)"
```

Upstream QEMU is not sufficient: the system requires this custom fork with the integrated `fx` device and KVM-side modifications.

---

### Create or prepare the Debian guest image

Prepare the Debian-based guest disk image used for the experiments:

```sh
./create-debianImg.sh
```

This step is typically executed only once, unless the guest filesystem needs to be regenerated.

---

### Run the system

Once all components have been built, launch the system using:

```sh
./runall.sh
```

This script:

* injects the guest bootstrap kernel module and `fx-boot.sh` into the guest   filesystem,
* installs a one-shot systemd unit for the trusted bootstrap phase,
* launches QEMU with the correct configuration.






