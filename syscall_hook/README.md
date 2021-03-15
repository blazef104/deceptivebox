# api_hook plugin

We will use this pulgin to hook api calls inside a windows guest.

The plugin is based on the functionalities exposed by osi and syscalls2. 

```sh
../../build/i386-softmmu/panda-system-i386 -m 3G -replay third -os windows_32_7 -panda 'osi;syscalls2;api_hook:name=notepad.exe'
```

to build panda 

```sh
../build.sh x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu --disable-werror --disable-pyperipheral3
```