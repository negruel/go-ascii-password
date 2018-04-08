# go-ascii-password

Simple ASCII password generator written in Go

Passwords are generated conforming to the passed rules defining the minimum length and minimum number of uppercase, lowercase, numbers, and special characters. Callers may override the list of allowable special characters.

Two methods are exposed:

__Generate:__ This method uses the random number generator exposed by math/rand

__GenerateStrong:__ This method uses the random number generator exposed by crypto/rand

## Example usage

```go

package main

import (
    "fmt"

    "github.com/negruel/go-ascii-password/password"
)

func main() {

    // instantiate a password struct with our ruleset
    pwd := password.Password{
        MinLength:    16,
        Upper:        1,
        Lower:        1,
        Number:       1,
        Symbol:       1,
        ValidSymbols: []rune("!@$&*()_-'"),
    }

    // call Generate to create a password conforming to the defined rules
    // using the random number generator in math/rand
    newPwd, err := pwd.Generate()

    // call GenerateStrong to create a password conforming to the defined rules
    // using the random number generator in crypto/rand
    // newPwd, err := pwd.GenerateStrong()

    if err != nil {
        fmt.Println(err)
    } else {
        fmt.Println(newPwd)
    }

}

```

```text

negruel$ go run main.go
(ma@*b1Q_T!9CKDu5

```

## Password Struct Values

### MinLength

- Set the minimum length of the generated password
- Must be >= 0.

### Upper

- Set the minimum number of upper case letters the password must include
- The ASCII letters A - Z are used
- Must be >= 0; set to 0 to include no upper case letters

### Lower

- Set the minimum number of lower case letters the password must include
- The ASCII letters a - z are used
- Must be >= 0; set to 0 to include no lower case letters

### Number

- Set the minimum number of numeric digits the password must include
- The numbers 0 - 9 are used
- Must be >= 0; set to 0 to include no numeric digits

### Symbols

- Set the minimum number of special symbols the password must include.
- Must be >= 0; set to 0 to include no numeric digits

### ValidSymbols

- Set the array of allowable symbols to use instead of the default list.
- The default symbols are __!@#$%^&*()-_=+[{]}|;:',\<.>/?"__.
- Must be nil or a []Rune with length > 0
- Pass nil to use the default symbols.
