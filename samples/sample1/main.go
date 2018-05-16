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
Purpose: sample commandline usage for password package

*/

package main

import (
	"flag"
	"fmt"

	"github.com/negruel/go-ascii-password/password"
)

var minPwdLen, minUpper, minLower, minNumber, minSpecial int
var spclChar, generator, pwd string
var err error

func init() {

	flag.IntVar(&minPwdLen, "len", 16, "Minimum password length")
	flag.StringVar(&spclChar, "spcl", password.Symbols, "Allowable special characters")
	flag.IntVar(&minUpper, "u", 1, "Minimum number of upper case characters")
	flag.IntVar(&minLower, "l", 1, "Minimum number of lower case characters")
	flag.IntVar(&minNumber, "n", 1, "Minimum number of numbers")
	flag.IntVar(&minSpecial, "s", 1, "Minimum number of special characters")
	flag.StringVar(&generator, "g", "c", "Random generator: c for crypto/rand; m for math/rand")

}

func main() {

	flag.Parse()

	var valSym []rune

	// check if special characters were provided. If so,
	// pass the list provided; otherwise; pass nill.
	if len(spclChar) == 0 {
		valSym = nil
	} else {
		valSym = []rune(spclChar)
	}

	password := password.Password{
		MinLength:    minPwdLen,
		Upper:        minUpper,
		Lower:        minLower,
		Number:       minNumber,
		Symbol:       minSpecial,
		ValidSymbols: valSym,
	}

	if generator == "c" {
		pwd, err = password.GenerateStrong()
	} else {
		pwd, err = password.Generate()
	}

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(pwd)
	}

}
