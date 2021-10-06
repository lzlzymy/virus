# virus

华科软件安全实验土质版病毒

**software security test**

```shell
go build -v -a -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}"

go build -v -a -ldflags="-w -s" -trimpath
```
