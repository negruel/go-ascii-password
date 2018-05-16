/*

Copyright 2018 Brian Gollwitzer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

File   : main.go
Package: main
Purpose: sample usage for password package

*/
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

	fmt.Println("------------------------------")
	fmt.Println("Password format rules")
	fmt.Println("------------------------------")
	fmt.Printf("MinLength = %v\n", pwd.MinLength)
	fmt.Printf("Upper = %v\n", pwd.Upper)
	fmt.Printf("Lower = %v\n", pwd.Lower)
	fmt.Printf("Number = %v\n", pwd.Number)
	fmt.Printf("Symbol = %v\n", pwd.Symbol)
	fmt.Printf("Valid Symbols = %v\n\n", string(pwd.ValidSymbols))

	// call Generate to create a password conforming to the defined rules
	// using the random number generator in math/rand
	newPwd, err := pwd.Generate()

	// output the password
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Password generated using Generate() = %v\n", newPwd)
	}

	// call GenerateStrong to create a password conforming to the defined rules
	// using the random number generator in crypto/rand
	newPwd, err = pwd.GenerateStrong()

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Password generated using GenerateStrong() = %v\n", newPwd)
	}

}
