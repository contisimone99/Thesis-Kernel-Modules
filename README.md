# Thesis-Kernel-Modules


### Prepare Linux subdirectory

Add the submodule to the repo and grab the 6.6LTS kernel version (it will take some time)
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

    # 2.1 enable memory hotplug
    scripts/config --enable CONFIG_MEMORY_HOTPLUG
    scripts/config --enable CONFIG_MEMORY_HOTREMOVE

    # 2.2 enable memory hotplug with auto-online
    scripts/config --enable CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE

    # 2.3 enable virtio-mem
    scripts/config --enable CONFIG_VIRTIO_MEM

    # 2.4 enable virtio support
    scripts/config --enable CONFIG_VIRTIO
    scripts/config --enable CONFIG_VIRTIO_PCI

    # 3. prepare necessary file for build
    make prepare

    # 4. prepare environment to compile modules
    make modules_prepare

    # 5. compile kernel image (bzImage)
    make -j"$(nproc)" bzImage

    # 6. compile kernel modules
    make -j"$(nproc)" modules
```





