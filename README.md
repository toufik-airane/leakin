**Secrets detection based on regular expressions.**

### Install
```bash
go get -v -u github.com/secopslab/leakin
```

### Use
```bash
~ leakin -f leaky-repo/
/leaky-repo/.bash_profile aws_patterns AWS_ACCESS_KEY_ID
/leaky-repo/.bash_profile aws_patterns AWS_SECRET_ACCESS_KEY
/leaky-repo/.bash_profile aws_patterns AWS_ACCESS_KEY_ID
/leaky-repo/.bash_profile aws_patterns AWS_SECRET_ACCESS_KEY
[...]
```
