# python-wmi-client-wrapper

This is a wrapper around wmi-client for Linux. Apparently the python-wmi module
uses Windows APIs to access WMI, which isn't something that is going to work on
Linux.

This fork version supports other wmic arguments like workgroup, namespace, etc.


## Requirements

wmi-client-wrapper needs wmic installed 

## installing

```
pip install wmi-client-wrapper
```

## usage

```
import wmi_client_wrapper as wmi

wmic = wmi.WmiClientWrapper(
    username="Administrator",
    password="password",
    host="192.168.1.149",
)

output = wmic.query("SELECT * FROM Win32_Processor")
```

example passing namespace
```
import wmi_client_wrapper as wmi

wmic = wmi.WmiClientWrapper(
    username="Administrator",
    password="password",
    host="192.168.1.149",
    workgroup="WORKGROUP",
    namespace='root\CIMV2'
)

output = wmic.query("SELECT * FROM Win32_Processor")
```


## testing

```
nosetests
```

## license

BSD
