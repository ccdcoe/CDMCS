# Hello, World!

See if go environment is configured and create the directory for your program
```
go env
mkdir -p $GOPATH/src/github.com/username/helloworld
cd $GOPATH/src/github.com/username/helloworld
touch helloworld.go
```

Add the following content to helloworld.go

```
package main

import "fmt"

func main() {
    fmt.Printf("Hello, world!\n")
}
```

```
go build
ls
./helloworld
```
