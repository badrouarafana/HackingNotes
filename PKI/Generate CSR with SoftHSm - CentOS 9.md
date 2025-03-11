## Soft hsm
install
```bash
# install soft hsm
dnf install softhsm -y
dnf install opensc
wget https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/openssl-pkcs11-0.4.11-9.el9.x86_64.rpm
yum install -y ./openssl-pkcs11-0.4.11-9.el9.x86_64.rpm
openssl engine -t -c pkcs11

```

list slots 
```bash
softhsm2-util --show-slots
```
init a new slot 
```bash
softhsm2-util --init-token --slot <Number of empty slot> --label "MyNewSlot"
# later we give so pin and user pin
```

find module
```bash
#get module
find / -name "libsofthsm2.so"
#get info
pkcs11-tool --show-info --module /usr/lib64/pkcs11/libsofthsm2.so
# get slots
pkcs11-tool --list-slots --module /usr/lib64/pkcs11/libsofthsm2.so
```
Generate key pair
```bash
# login to slot first
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so --slot 0x2e66d7f9 --login
#list all slots
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so -T -O -I 
#list specific slot
pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so --slot 0x2e66d7f9 --list-object --login
#generate keys
pkcs11-tool --module  /usr/lib64/pkcs11/libsofthsm2.so   -l --token-label "centos server" -k --key-type rsa:2048 --id 1001 --label "centos-key"
```

Finally generate the CSR 

```bash
# Give the key ID 
openssl req -engine pkcs11 -new -key 1001 -keyform engine -out mydomain.csr -subj "/CN=mydomain.com/O=MyOrganization/C=US"
```
