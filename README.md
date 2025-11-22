# Thesis-Kernel-Modules


### Prepare Linux subdirectory

Add the submodule to the repo and grab the 6.6LTS kernel version (it will take some time)
```sh
    git submodule add https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux
    cd linux
    git fetch --all --tags
    git checkout v6.6

```
Check that it is the correct version

```sh
    git describe --tags
```
You should see something like the following output:

```sh
    v6.6
```

Now prepare all the headers
```sh
    make mrproper
    make olddefconfig
    make prepare
```


