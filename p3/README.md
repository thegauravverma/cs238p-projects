##Create file via following command

```
dd if=/dev/zero of=file bs=4096 count=100000
```

###Current Issues
1. First SCM malloc is failing,next few are working.
2. Need to add error check for signature
3. Truncate is not working 

